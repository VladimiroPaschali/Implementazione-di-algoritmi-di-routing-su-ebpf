/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader and stats program\n"
	" - Allows selecting BPF section --progsec name to XDP-attach to --dev\n";
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <locale.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h> /* depend on kernel-headers installed */
#include "../common/common_params.h"
#include "../common/common_user_bpf_xdp.h"
#include "common_kern_user.h"
#include "bpf_util.h" /* bpf_num_possible_cpus */
#include <arpa/inet.h>
#include <assert.h>
static const char *default_filename = "xdp_prog_kern.o";
static const char *default_progsec = "xdp_stats1";
static const struct option_wrapper long_options[] = {
	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},
	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},
	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},
	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},
	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},
	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},
	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},
	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},
	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},
	{{"progsec",    required_argument,	NULL,  2  },
	 "Load program in <section> of the ELF file", "<section>"},
	{{0, 0, NULL,  0 }}
};
//restituisce il file descriptor della mappa che si trova nel programma kernel
int find_map_fd(struct bpf_object *bpf_obj, const char *mapname)
{
	struct bpf_map *map;
	int map_fd = -1;
	map = bpf_object__find_map_by_name(bpf_obj, mapname);
        if (!map) {
		fprintf(stderr, "ERR: cannot find map by name: %s\n", mapname);
		goto out;
	}
	map_fd = bpf_map__fd(map);
 out:
	return map_fd;
}

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
	struct timespec t;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &t);
	if (res < 0) {
		fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
		exit(EXIT_FAIL);
	}
	return (__u64) t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}
//struct per il salvataggio dei dati da stampare
struct record {
	__u64 timestamp;
	struct datarec total; /* defined in common_kern_user.h */
};
//insieme di record uno per ogni mappa
struct stats_record {
	struct record stats[33];
};

static double calc_period(struct record *r, struct record *p)
{
	double period_ = 0;
	__u64 period = 0;

	period = r->timestamp - p->timestamp;
	if (period > 0)
		period_ = ((double) period / NANOSEC_PER_SEC);

	return period_;
}
static void stats_print_header()
{
	printf("%-12s\n", "Mappa Valori Totali");
}
//stampa le statistiche, pacchetti totali elaborati, pacchetti per secondo elaborati,
//MB totali, MB/s
static void stats_print(struct stats_record *stats_rec,
			struct stats_record *stats_prev)
{
	struct record *rec, *prev;
	__u64 packets, bytes;
	double period;
	double pps; /* packets per sec */
	double bps; /* bits per sec */
	int i;

	stats_print_header(); /* Print stats "header" */

	/* stampa per ogni mappa */
	for (i = 0; i < 33; i++)
	{
		char *fmt = "%-12s %'11lld pkts (%'10.0f pps)"
			" %'11lld Kbytes (%'6.0f Mbits/s)"
			" period:%f\n";
		char action[10];
		sprintf(action,"%d",i);

		rec  = &stats_rec->stats[i];
		prev = &stats_prev->stats[i];

		period = calc_period(rec, prev);
		if (period == 0)
		       return;

		packets = rec->total.rx_packets - prev->total.rx_packets;
		pps     = packets / period;

		bytes   = rec->total.rx_bytes   - prev->total.rx_bytes;
		bps     = (bytes * 8)/ period / 1000000;

		printf(fmt, action, rec->total.rx_packets, pps,
		       rec->total.rx_bytes / 1000 , bps,
		       period);
	}
}

/* BPF_MAP_TYPE_PERCPU_ARRAY */
void map_get_value_percpu_array(int fd, __u32 key, struct datarec *value)
{
	/* For percpu maps, userspace gets a value per possible CPU */
	unsigned int nr_cpus = bpf_num_possible_cpus();
	struct datarec values[nr_cpus];
	__u64 sum_bytes = 0;
	__u64 sum_pkts = 0;
	int i;

	if ((bpf_map_lookup_elem(fd, &key, values)) != 0) {
		fprintf(stderr,
			"ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
		return;
	}

	/* Somma le statistiche per ogni mappa */
	for (i = 0; i < nr_cpus; i++) {
		sum_pkts  += values[i].rx_packets;
		sum_bytes += values[i].rx_bytes;
	}
	value->rx_packets = sum_pkts;
	value->rx_bytes   = sum_bytes;
}
static bool map_collect(int fd, __u32 map_type, __u32 key, struct record *rec)
{
	struct datarec value;
	/* Get time as close as possible to reading map contents */
	rec->timestamp = gettime();
	switch (map_type) {
	case BPF_MAP_TYPE_PERCPU_ARRAY:
		map_get_value_percpu_array(fd, key, &value);
		break;
	default:
		fprintf(stderr, "ERR: Unknown map_type(%u) cannot handle\n",
			map_type);
		return false;
		break;
	}
	rec->total.rx_packets = value.rx_packets;
	rec->total.rx_bytes   = value.rx_bytes;
	return true;
}
//salva il valore per ognuno dei 33 array nella mappa
static void stats_collect(int map_fd, __u32 map_type,
			  struct stats_record *stats_rec)
{
	__u32 key;
	for (key = 0; key <33; key++) {
		map_collect(map_fd, map_type, key, &stats_rec->stats[key]);
	}
}

static void stats_poll(int map_dati_fd, __u32 map_type, int interval)
{
	struct stats_record prev0, record0 = { 0 };
	/* Trick to pretty printf with thousands separators use %' */
	setlocale(LC_NUMERIC, "en_US");
	/* Print stats "header" */
	if (verbose) {
		printf("\n");
		printf("%-12s\n", "XDP-action");
	}
	while (1) {
		prev0 = record0; /* struct copy */
		stats_collect(map_dati_fd, map_type, &record0);
		stats_print(&record0, &prev0);
		sleep(2);
	}
}
//controlla File descriptor e che la grandezza chiave valore corrisponda
static int __check_map_fd_info(int map_fd, struct bpf_map_info *info,
			       struct bpf_map_info *exp)
{
	__u32 info_len = sizeof(*info);
	int err;
	if (map_fd < 0)
		return EXIT_FAIL;
        /* BPF-info via bpf-syscall */
	err = bpf_obj_get_info_by_fd(map_fd, info, &info_len);
	if (err) {
		fprintf(stderr, "ERR: %s() can't get info - %s\n",
			__func__,  strerror(errno));
		return EXIT_FAIL_BPF;
	}
	if (exp->key_size && exp->key_size != info->key_size) {
		fprintf(stderr, "ERR: %s() "
			"Map key size(%d) mismatch expected size(%d)\n",
			__func__, info->key_size, exp->key_size);
		return EXIT_FAIL;
	}
	if (exp->value_size && exp->value_size != info->value_size) {
		fprintf(stderr, "ERR: %s() "
			"Map value size(%d) mismatch expected size(%d)\n",
			__func__, info->value_size, exp->value_size);
		return EXIT_FAIL;
	}
	if (exp->max_entries && exp->max_entries != info->max_entries) {
		fprintf(stderr, "ERR: %s() "
			"Map max_entries(%d) mismatch expected size(%d)\n",
			__func__, info->max_entries, exp->max_entries);
		return EXIT_FAIL;
	}
	if (exp->type && exp->type  != info->type) {
		fprintf(stderr, "ERR: %s() "
			"Map type(%d) mismatch expected type(%d)\n",
			__func__, info->type, exp->type);
		return EXIT_FAIL;
	}

	return 0;
}
//legge i valori in mappa/num.txt li converte e li salva nelle relative mappe
void mappa(int fdtrie, int fd24 ){
	__u64 counttot=0;
	//__u8 pass = XDP_PASS;//azione di default
	//__u8 value =XDP_PASS;
	__u8 uno = 1;
	__u8 zero = 0;
	size_t key_size_ipv4;
	struct bpf_lpm_trie_key *key_ipv4;
	key_size_ipv4 = sizeof(*key_ipv4) + sizeof(__u32);
	key_ipv4 = alloca(key_size_ipv4);




	for(int i=24; i<=32;i++){
		__u64 count=0;


		FILE * fp;
		char stringa[50];
		sprintf(stringa,"mappe/%d.txt",i);
		fp=fopen(stringa,"r");
		char * line = NULL;
	    	size_t len = 0;
	    	ssize_t read;
	    	if (fp == NULL){
			printf("mappa n %d non trovata\n",i);
			continue;
		}
		while ((read = getline(&line, &len, fp)) != -1) {


			//elimina \n da line
			line[strcspn(line,"\n")]=0;

		  	//__u32 ip = sa_param.sin_addr.s_addr;
		  	//printf("mappa %d ip %s ipconvertito %hhn\n",i,line,key_ipv4->data);
			struct sockaddr_in sa_param;
	  		inet_pton(AF_INET, line, &(sa_param.sin_addr));
	  		__u32 ip = sa_param.sin_addr.s_addr;
	  		//mascherato con 255.255.255.0
	  		__u32 ipmascherato = ip&16777215;
			if(i==24){
		  		assert(bpf_map_update_elem(fd24,&ipmascherato,&zero,BPF_ANY)==0);
			}else{
				//se presente nella mappa 24
				__u8 value;
				bpf_map_lookup_elem(fd24,&ipmascherato,&value);
				if(value==0){
		  			assert(bpf_map_update_elem(fd24,&ipmascherato,&uno,BPF_EXIST)==0);
					key_ipv4->prefixlen = i;
			  		inet_pton(AF_INET, line, key_ipv4->data);
					assert(bpf_map_update_elem(fdtrie,key_ipv4,&i,BPF_ANY)==0);
				}
				//non presente nella mappa /24
				else{
					key_ipv4->prefixlen = i;
			  		inet_pton(AF_INET, line, key_ipv4->data);
					assert(bpf_map_update_elem(fdtrie,key_ipv4,&i,BPF_ANY)==0);
				}
			}

			count++;
			counttot++;


	    	}
		fclose(fp);
	    	if (line)
		free(line);
		printf("Numero regole in mappa %d = %llu Numero totale = %llu\n",i,count,counttot);


	    	//printf("fine\n");


	}
	return;
}
int main(int argc, char **argv)
{
	struct bpf_map_info map_expect = { 0 };
	struct bpf_map_info info = { 0 };
	struct bpf_object *bpf_obj;
	int interval = 2;
	int err;
	struct config cfg = {
		.xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_DRV_MODE,
		.ifindex   = -1,
		.do_unload = false,
	};

	/* Set default BPF-ELF object file and BPF program name */
	strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	strncpy(cfg.progsec,  default_progsec,  sizeof(cfg.progsec));
	/* Cmdline options can change progsec */
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);
	/* Required option */
	if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}
	if (cfg.do_unload)
		return xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
	bpf_obj = load_bpf_and_xdp_attach(&cfg);
	if (!bpf_obj)
		return EXIT_FAIL_BPF;
	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used section(%s)\n",
		       cfg.filename, cfg.progsec);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}
  	int map_dati_fd;
	int map_lpm_fd;
	int map_lpm24_fd;
	//cerca i file descriptor delle mappe nel kernel
	map_lpm_fd = find_map_fd(bpf_obj, "lpm");
	if (map_lpm_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm24_fd = find_map_fd(bpf_obj, "lpm24");
	if (map_lpm24_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	//inserisce gli ip nelle relative mappe
	mappa(map_lpm_fd,map_lpm24_fd);
	map_dati_fd = find_map_fd(bpf_obj, "dati");
	if (map_dati_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	//controllo correttezza tipi chiave e valore mappe
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(struct datarec);
	map_expect.max_entries = 33;
	err = __check_map_fd_info(map_dati_fd, &info, &map_expect);
	if (err) {
		fprintf(stderr, "ERR: map via FD not compatible\n");
		return err;
	}
	if (verbose) {
		printf("\nCollecting stats from BPF map\n");
		printf(" - BPF map (bpf_map_type:%d) id:%d name:%s"
		       " key_size:%d value_size:%d max_entries:%d\n",
		       info.type, info.id, info.name,
		       info.key_size, info.value_size, info.max_entries
		       );
	}
	//recupera e stampa i dati
	stats_poll(map_dati_fd,info.type, interval);
	return EXIT_OK;
}