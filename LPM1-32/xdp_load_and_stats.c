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

	/*stampa per ogni mappa */
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

	/* Somma le statistiche per ogni core */
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
void mappa(int fds[]){
	__u64 counttot=0;
	__u8 pass = XDP_PASS;//azione di default
	//legge i file da 1 a 32 nella cartella mappe
	for(int i=1; i<=32;i++){
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
			//convete gli ip da formato decimale puntato a binario
			struct sockaddr_in sa_param;
		  	inet_pton(AF_INET, line, &(sa_param.sin_addr));
		  	__u32 ip = sa_param.sin_addr.s_addr;
			//carica i valori nnella mappa con chiave l'ip e valore pass
		  	assert(bpf_map_update_elem(fds[i-1],&ip,&pass,BPF_ANY)==0);
			count++;
			counttot++;

	    	}
		fclose(fp);
	    	if (line)
		free(line);
		printf("Numero regole in mappa %d = %llu Numero totale = %llu\n",i,count,counttot);
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
  	int map_0_fd;
	int map_1_fd;
	int map_lpm32_fd;
	int map_lpm31_fd;
	int map_lpm30_fd;
	int map_lpm29_fd;
	int map_lpm28_fd;
	int map_lpm27_fd;
	int map_lpm26_fd;
	int map_lpm25_fd;
	int map_lpm24_fd;
	int map_lpm23_fd;
	int map_lpm22_fd;
	int map_lpm21_fd;
	int map_lpm20_fd;
	int map_lpm19_fd;
	int map_lpm18_fd;
	int map_lpm17_fd;
	int map_lpm16_fd;
	int map_lpm15_fd;
	int map_lpm14_fd;
	int map_lpm13_fd;
	int map_lpm12_fd;
	int map_lpm11_fd;
	int map_lpm10_fd;
	int map_lpm9_fd;
	int map_lpm8_fd;
	int map_lpm7_fd;
	int map_lpm6_fd;
	int map_lpm5_fd;
	int map_lpm4_fd;
	int map_lpm3_fd;
	int map_lpm2_fd;
	int map_lpm1_fd;



	//cerca i file descriptor delle mappe nel kernel
	map_lpm32_fd = find_map_fd(bpf_obj, "lpm32");
	if (map_lpm32_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm31_fd = find_map_fd(bpf_obj, "lpm31");
	if (map_lpm31_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm30_fd = find_map_fd(bpf_obj, "lpm30");
	if (map_lpm30_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm29_fd = find_map_fd(bpf_obj, "lpm29");
	if (map_lpm29_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm28_fd = find_map_fd(bpf_obj, "lpm28");
	if (map_lpm28_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm27_fd = find_map_fd(bpf_obj, "lpm27");
	if (map_lpm27_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm26_fd = find_map_fd(bpf_obj, "lpm26");
	if (map_lpm26_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm25_fd = find_map_fd(bpf_obj, "lpm25");
	if (map_lpm25_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm24_fd = find_map_fd(bpf_obj, "lpm24");
	if (map_lpm24_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm23_fd = find_map_fd(bpf_obj, "lpm23");
	if (map_lpm23_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm22_fd = find_map_fd(bpf_obj, "lpm22");
	if (map_lpm22_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm21_fd = find_map_fd(bpf_obj, "lpm21");
	if (map_lpm21_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm20_fd = find_map_fd(bpf_obj, "lpm20");
	if (map_lpm20_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm19_fd = find_map_fd(bpf_obj, "lpm19");
	if (map_lpm19_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm18_fd = find_map_fd(bpf_obj, "lpm18");
	if (map_lpm18_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm17_fd = find_map_fd(bpf_obj, "lpm17");
	if (map_lpm17_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm16_fd = find_map_fd(bpf_obj, "lpm16");
	if (map_lpm16_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm15_fd = find_map_fd(bpf_obj, "lpm15");
	if (map_lpm15_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm14_fd = find_map_fd(bpf_obj, "lpm14");
	if (map_lpm14_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm13_fd = find_map_fd(bpf_obj, "lpm13");
	if (map_lpm13_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm12_fd = find_map_fd(bpf_obj, "lpm12");
	if (map_lpm12_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm11_fd = find_map_fd(bpf_obj, "lpm11");
	if (map_lpm11_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm10_fd = find_map_fd(bpf_obj, "lpm10");
	if (map_lpm10_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm9_fd = find_map_fd(bpf_obj, "lpm9");
	if (map_lpm9_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm8_fd = find_map_fd(bpf_obj, "lpm8");
	if (map_lpm8_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm7_fd = find_map_fd(bpf_obj, "lpm7");
	if (map_lpm7_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm6_fd = find_map_fd(bpf_obj, "lpm6");
	if (map_lpm6_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm5_fd = find_map_fd(bpf_obj, "lpm5");
	if (map_lpm5_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm4_fd = find_map_fd(bpf_obj, "lpm4");
	if (map_lpm4_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm3_fd = find_map_fd(bpf_obj, "lpm3");
	if (map_lpm3_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm2_fd = find_map_fd(bpf_obj, "lpm2");
	if (map_lpm2_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}
	map_lpm1_fd = find_map_fd(bpf_obj, "lpm1");
	if (map_lpm1_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	int fds[]={map_lpm1_fd,map_lpm2_fd,map_lpm3_fd,map_lpm4_fd,map_lpm5_fd,map_lpm6_fd,map_lpm7_fd,map_lpm8_fd,map_lpm9_fd,map_lpm10_fd,map_lpm11_fd,map_lpm12_fd,map_lpm13_fd,map_lpm14_fd,
	map_lpm15_fd,map_lpm16_fd,map_lpm17_fd,map_lpm18_fd,map_lpm19_fd,map_lpm20_fd,map_lpm21_fd,map_lpm22_fd,map_lpm23_fd,map_lpm24_fd,map_lpm25_fd,map_lpm26_fd,map_lpm27_fd,
	map_lpm28_fd,map_lpm29_fd,map_lpm30_fd,map_lpm31_fd,map_lpm32_fd};

	//inserisce gli ip nelle relative mappe
	mappa(fds);


	map_dati_fd = find_map_fd(bpf_obj, "dati");
	if (map_dati_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	map_0_fd = find_map_fd(bpf_obj, "zero");
	if (map_0_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}

	map_1_fd = find_map_fd(bpf_obj, "uno");
	if (map_1_fd < 0) {
		xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
		return EXIT_FAIL_BPF;
	}




	//controllo correttezza tipi chiave e valore mappe
	map_expect.key_size    = sizeof(__u32);
	map_expect.value_size  = sizeof(struct datarec);
	map_expect.max_entries = XDP_ACTION_MAX;
	err = __check_map_fd_info(map_1_fd, &info, &map_expect);
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


	stats_poll(map_dati_fd,info.type, interval);

	return EXIT_OK;
}