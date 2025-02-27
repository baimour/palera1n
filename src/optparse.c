#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <assert.h>
#include <getopt.h>
#include <limits.h>
#include <errno.h>
#include <palerain.h>
#include <sys/mman.h>
#include <inttypes.h>
#ifdef TUI
#include <tui.h>
#endif

uint64_t* palerain_flags_p = &palerain_flags;
char* gOverrideLibcheckra1nHelper = NULL;

static struct option longopts[] = {
	{"setup-partial-fakefs", no_argument, NULL, 'B'},
	{"setup-fakefs", no_argument, NULL, 'c'},
	{"clean-fakefs", no_argument, NULL, 'C'},
	{"dfuhelper", no_argument, NULL, 'D'},
	{"help", no_argument, NULL, 'h'},
	{"pongo-shell", no_argument, NULL, 'p'},
	{"pongo-full", no_argument, NULL, 'P'},
	{"debug-logging", no_argument, NULL, 'v'},
	{"verbose-boot", no_argument, NULL, 'V'},
	{"boot-args", required_argument, NULL, 'e'},
	{"fakefs", no_argument, NULL, 'f'},
	{"rootless", no_argument, NULL, 'l'},
	{"demote", no_argument, NULL, 'd'},
	{"force-revert", no_argument, NULL, palerain_option_case_force_revert},
	{"no-colors", no_argument, NULL, 'S'},
	{"safe-mode", no_argument, NULL, 's'},
	{"telnetd", no_argument, NULL, 'T'},
	{"version", no_argument, NULL, palerain_option_case_version},
	{"override-libcheckra1nhelper", required_argument, NULL, palerain_option_case_libcheckra1nhelper_path},
	{"override-pongo", required_argument, NULL, 'k'},
	{"override-overlay", required_argument, NULL, 'o'},
	{"override-ramdisk", required_argument, NULL, 'r'},
	{"override-kpf", required_argument, NULL, 'K'},
	{"override-checkra1n", required_argument, NULL, 'i'},
	{"reboot-device", no_argument, NULL, 'R'},
	{"exit-recovery", no_argument, NULL, 'n'},
	{"enter-recovery", no_argument, NULL, 'E'},
	{"device-info", no_argument, NULL, 'I'},
#ifdef DEV_BUILD
	{"test1", no_argument, NULL, '1'},
	{"test2", no_argument, NULL, '2'},
#endif
#ifdef TUI
	{"tui", no_argument, NULL, 't'},
#endif
	{"cli", no_argument, NULL, palerain_option_case_cli},
	{NULL, 0, NULL, 0}
};

static int usage(int e, char* prog_name)
{
	fprintf(stderr,
	"使用方法: %s [-"
	"DEhpvVldsSTLRnPI"
#ifdef DEV_BUILD
			"12"
#endif
#ifdef ROOTFUL
			"cCfB"
#endif
#ifdef TUI
			"t"
#endif
			"] [-e 引导参数] [-k Pongo图像] [-o 叠加文件] [-r ramdisk文件] [-K KPF文件] [-i checkra1n文件]\n"
			"Copyright (C) 2024, palera1n team, All Rights Reserved.\n\n"
			"iOS/iPadOS/tvOS 15.0-18.3, bridgeOS 5.0-9.3 arm64越狱工具\n\n"
			"\t--version\t\t\t\t显示版本\n"
			"\t--force-revert\t\t\t\t移除越狱\n"
#ifdef DEV_BUILD
			"\t-1, --test1\t\t\t\t设置palerain选项测试1\n"
			"\t-2, --test2\t\t\t\t设置palerain选项测试2\n"
#endif
#ifdef ROOTFUL
			"\t-B, --setup-partial-fakefs\t\t设置部分fakefs\n"
			"\t-c, --setup-fakefs\t\t\t设置fakefs\n"
			"\t-C, --clean-fakefs\t\t\t清理fakefs\n"
#endif
			"\t-d, --demote\t\t\t\tDemote\n"
			"\t-D, --dfuhelper\t\t\t\t进入DFU后退出\n"
			"\t-e, --boot-args <引导参数>\tXNU引导参数\n"
			"\t-E, --enter-recovery\t\t\t进入恢复模式\n"
#ifdef ROOTFUL
			"\t-f, --fakefs \t\t\t\t引导fakefs\n"
#endif
			"\t-h, --help\t\t\t\t显示使用帮助\n"
			"\t-i, --override-checkra1n <file>\t\t覆盖checkra1n\n"
			"\t-k, --override-pongo <文件>\t\t覆盖Pongo图像\n"
			"\t-K, --override-kpf <文件>\t\t覆盖内核补丁查找器\n"
#ifdef ROOTFUL
			"\t-l, --rootless\t\t\t\t引导Rootless，这是默认的\n"
#endif
			"\t-L, --jbinit-log-to-file\t\t将jbinit日志记录到/cores/jbinit.log (越狱后可以从沙盒中读取)\n"
			"\t-n, --exit-recovery\t\t\t退出恢复模式\n"
			"\t-I, --device-info\t\t\t输出已连接设备的信息\n"
			"\t-o, --override-overlay <文件>\t\t覆盖叠加\n"
			"\t-p, --pongo-shell\t\t\t引导至PongoOS Shell\n"
			"\t-P, --pongo-full\t\t\t引导到已上传默认图像的PongoOS Shell\n"
			"\t-r, --override-ramdisk <文件>\t\t覆盖ramdisk\n"
			"\t-R, --reboot-device\t\t\t在正常模式重启已连接的设备\n"
			"\t-s, --safe-mode\t\t\t\t进入安全模式\n"
			"\t-S, --no-colors\t\t\t\t在命令行上禁用颜色\n"
			"\t-T, --telnetd\t\t\t\t在端口46上启用TELNET守护程序 (insecure)\n"
			"\t-v, --debug-logging\t\t\t启用调试日志记录\n"
			"\t\t这个选项可以重复，以增加冗余\n"
			"\t-V, --verbose-boot\t\t\t详细引导\n"

#ifdef TUI
			"\t-t, --tui\t\t\t\t强制互动TUI\n"
			"\t--cli\t\t\t\t\t强制cli模式\n"
#endif
		"\n环境变量:\n"
		"\tTMPDIR\t\t临时目录 (内置checkra1n的路径将被提取到)\n"
			,
			prog_name);
	exit(e);
}

int optparse(int argc, char* argv[]) {
	int opt;
	int index;
	while ((opt = getopt_long(argc, argv,
	"DEhpvVlLdsSTtRnPIe:o:r:K:k:i:"
#ifdef DEV_BUILD
	"12"
#endif
#ifdef ROOTFUL
	"fCcB"
#endif
	,longopts, NULL)) != -1)
	{
		switch (opt) {
#ifdef ROOTFUL
		case 'B':
			palerain_flags |= palerain_option_setup_partial_root;
			palerain_flags |= palerain_option_setup_rootful;
			break;
		case 'c':
			palerain_flags |= palerain_option_setup_rootful;
			break;
		case 'C':
			palerain_flags |= palerain_option_clean_fakefs;
			break;
#endif
		case 'p':
			palerain_flags |= palerain_option_pongo_exit;
			break;
		case 'P':
			palerain_flags |= palerain_option_pongo_full;
			break;
		case 'D':
			palerain_flags |= palerain_option_dfuhelper_only;
			break;
		case 'h':
			usage(0, argv[0]);
			assert(0);
		case 'v':
			verbose++;
			break;
		case 'V':
			palerain_flags |= palerain_option_verbose_boot;
#ifdef TUI
			tui_options_verbose_boot = true;
#endif
			break;
		case 'e':
			if (strlen(optarg) > (sizeof(xargs_cmd) - 0x20)) {
                LOG(LOG_FATAL, "引导参数过长");
                return -1;
            }
			snprintf(xargs_cmd, sizeof(xargs_cmd), "xargs %s", optarg);
#ifdef TUI
			snprintf(tui_options_boot_args, sizeof(tui_options_boot_args), "%s", optarg);
#endif
			break;
#ifdef ROOTFUL
		case 'f':
			palerain_flags |= palerain_option_rootful;
			palerain_flags &= ~palerain_option_rootless;
			break;
#endif
		case 'l':
			palerain_flags &= ~palerain_option_rootful;
			palerain_flags |= palerain_option_rootless;
			break;
		case 'L':
			palerain_flags |= palerain_option_jbinit_log_to_file;
			break;
		case 'd':
			palerain_flags |= palerain_option_demote;
			break;
		case 'E':
			palerain_flags |= palerain_option_enter_recovery;
			break;
		case 's':
			palerain_flags |= palerain_option_safemode;
#ifdef TUI
			tui_options_safe_mode = true;
#endif
			break;
		case 'T':
			palerain_flags |= palerain_option_telnetd;
			break;
		case 'k':
			if (access(optarg, F_OK) != 0) {
				LOG(LOG_FATAL, "无法访问%s的pongo文件: %d (%s)", optarg, errno, strerror(errno));
				return -1;
			}
			pongo_path = malloc(strlen(optarg) + 1);
			if (pongo_path == NULL) {
				LOG(LOG_FATAL, "内存分配失败");
				return -1;
			}
			snprintf(pongo_path, strlen(optarg) + 1, "%s", optarg);
			break;
		case 'o':
			if (override_file(&override_overlay, overlay_to_upload, &binpack_dmg_len, optarg))
				return 1;
			break;
		case 'r':
			if (override_file(&override_ramdisk, ramdisk_to_upload, &ramdisk_dmg_lzma_len, optarg))
				return 1;
			break;
		case 'K':
			if (override_file(&override_kpf, kpf_to_upload, &checkra1n_kpf_pongo_lzma_len, optarg))
				return 1;
			struct mach_header_64* hdr = (struct mach_header_64*)override_kpf.ptr;
			if (hdr->magic != MH_MAGIC_64 && hdr->magic != MH_CIGAM_64) {
				LOG(LOG_FATAL, "内核补丁查找器无效: 不薄的64位Mach-O");
				return -1;
			} else if (hdr->filetype != MH_KEXT_BUNDLE) {
				LOG(LOG_FATAL, "内核补丁查找器无效: 不是kext包");
				return -1;
			} else if (hdr->cputype != CPU_TYPE_ARM64) {
				LOG(LOG_FATAL, "内核查找器无效: CPU类型不是arm64");
				return -1;
			}
			break;
		case 'i': {};
			struct stat st;
			if (stat(optarg, &st) != 0) {
				LOG(LOG_FATAL, "无法统计外部checkra1n文件: %d (%s)", errno, strerror(errno));
				return -1;
			} else if (!(st.st_mode & S_IXUSR) && !(st.st_mode & S_IXGRP) && !(st.st_mode & S_IXOTH)) {
				LOG(LOG_FATAL, "%s不可执行", optarg);
				return -1;
			} else if (!S_ISREG(st.st_mode)) {
				LOG(LOG_FATAL, "%s不是常规文件", optarg);
				return -1;
			}
			if (st.st_size < (UCHAR_MAX+1)) {
				LOG(LOG_FATAL, "%s太小", optarg);
				return -1;
			}
			int checkra1n_fd = open(optarg, O_RDONLY);
			if (checkra1n_fd == -1) {
				LOG(LOG_FATAL, "无法打开%s: %d (%s)", optarg, errno, strerror(errno));
				return -1;
			}
			void* addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, checkra1n_fd, 0);
			if (addr == MAP_FAILED) {
				LOG(LOG_ERROR, "映射文件失败%s: %d (%s)", optarg, errno, strerror(errno));
				return -1;
			}
			if (boyermoore_horspool_memmem(addr, st.st_size, (const unsigned char*)"[ra1npoc15-part] thanks to", strlen("[ra1npoc15-part] thanks to")) != NULL) 
				{
					palerain_flags |= palerain_option_checkrain_is_clone;
					LOG(LOG_VERBOSE3, "%s是checkra1n克隆", optarg);
				}
			else
			{
				palerain_flags &= ~palerain_option_checkrain_is_clone;
				LOG(LOG_VERBOSE3, "%s是checkra1n", optarg);
			}
			munmap(addr, st.st_size);
			close(checkra1n_fd);
			ext_checkra1n = calloc(1, strlen(optarg) + 1);
			snprintf(ext_checkra1n, strlen(optarg) + 1, "%s", optarg);
			break;
		case 'R':
			palerain_flags |= palerain_option_reboot_device;
			break;
		case 'n':
			palerain_flags |= palerain_option_exit_recovery;
			break;
		case 'I':
			palerain_flags |= palerain_option_device_info;
			break;
		case 'S':
			palerain_flags |= palerain_option_no_colors;
			break;
#ifdef TUI
		case 't':
			palerain_flags |= palerain_option_tui;
			break;
#endif
		case palerain_option_case_cli:
			palerain_flags |= palerain_option_cli;
			break;
#ifdef DEV_BUILD
		case '1':
			palerain_flags |= palerain_option_test1;
			break;
		case '2':
			palerain_flags |= palerain_option_test2;
			break;
#endif
		case palerain_option_case_force_revert:
			palerain_flags |= palerain_option_force_revert;
#ifdef TUI
			tui_options_force_revert = true;
#endif
			break;
		case palerain_option_case_version:
			palerain_flags |= palerain_option_palerain_version;
			break;
		case palerain_option_case_libcheckra1nhelper_path:
			printf("meow\n");
			gOverrideLibcheckra1nHelper = calloc(1, strlen(optarg) + 1);
			if (!gOverrideLibcheckra1nHelper) {
				return -1;
			}
			snprintf(gOverrideLibcheckra1nHelper, strlen(optarg) + 1, "%s", optarg);
			break;
		default:
			usage(1, argv[0]);
			break;
		}
	}
	if ((palerain_flags & palerain_option_palerain_version)) {
		printf(
			"palera1n " PALERAIN_VERSION "\n"
			BUILD_COMMIT " " BUILD_NUMBER " (" BUILD_BRANCH ")\n\n"
			"构建风格: " BUILD_STYLE "\n"
			"构建标签: " BUILD_TAG "\n"
#ifdef USE_LIBUSB
			"USB后端: libusb\n"
#else
			"USB后端: IOKit\n"
#endif
			"构建选项: " BUILD_OPTIONS "\n"
		);
		return 0;
	}

	if (palerain_flags & palerain_option_telnetd) {
		LOG(LOG_WARNING, "Telnetd已启用，这是一个安全漏洞");
	}

	if ((palerain_flags & (palerain_option_tui)) && (palerain_flags & (palerain_option_cli))) {
		LOG(LOG_FATAL, "不能同时指定--tui和--cli");
		return -1;
	}

	if ((palerain_flags & (palerain_option_exit_recovery | palerain_option_enter_recovery | palerain_option_reboot_device | palerain_option_device_info | palerain_option_dfuhelper_only | palerain_option_pongo_exit | palerain_option_pongo_full)) > 0) {
		palerain_flags &= ~palerain_option_tui;
		palerain_flags |= palerain_option_cli;
	} else {
#ifdef ROOTFUL
		if ((palerain_flags & (palerain_option_rootless | palerain_option_rootful)) == 0) {
			LOG(LOG_FATAL, "请指定rootful (-f) 或 rootless (-l)");
			return -1;
		}
#else
		palerain_flags |= palerain_option_rootless;
#endif
	}
    
	snprintf(palerain_flags_cmd, 0x30, "palera1n_flags 0x%" PRIx64, palerain_flags);
	LOG(LOG_VERBOSE3, "palerain_flags: %s", palerain_flags_cmd);
	if (override_kpf.magic == OVERRIDE_MAGIC) {
		LOG(LOG_VERBOSE4, "kpf override length %" PRIu32 " -> %" PRIu32, override_kpf.orig_len, checkra1n_kpf_pongo_lzma_len);
		LOG(LOG_VERBOSE4, "kpf override ptr %p -> %p", override_kpf.orig_ptr, **kpf_to_upload);
	}
	if (override_ramdisk.magic == OVERRIDE_MAGIC) {
		LOG(LOG_VERBOSE4, "ramdisk override length %" PRIu32 " -> %" PRIu32, override_ramdisk.orig_len, ramdisk_dmg_lzma_len);
		LOG(LOG_VERBOSE4, "ramdisk override ptr %p -> %p", override_ramdisk.orig_ptr, **ramdisk_to_upload);
	}
	if (override_overlay.magic == OVERRIDE_MAGIC) {
		LOG(LOG_VERBOSE4, "overlay override length %" PRIu32 " -> %" PRIu32, override_overlay.orig_len, binpack_dmg_len);
		LOG(LOG_VERBOSE4, "overlay override ptr %p -> %p", override_overlay.orig_ptr, **overlay_to_upload);
	}
#ifdef ROOTFUL
	if (!(palerain_flags & palerain_option_rootful)) {
		if ((palerain_flags & palerain_option_setup_rootful)) {
			LOG(LOG_FATAL, "指定了rootless时，无法设置rootful。使用-f启用rootful模式");
			return -1;
		}
	}
#endif
	if (!(
			(palerain_flags & palerain_option_dfuhelper_only) ||
			(palerain_flags & palerain_option_enter_recovery) ||
			(palerain_flags & palerain_option_exit_recovery) ||
			(palerain_flags & palerain_option_reboot_device)))
	{
#ifdef NO_CHECKRAIN
		if (checkra1n_len == 0 && ext_checkra1n == NULL)
		{
			LOG(LOG_FATAL, "Checkra1n在构建中省略，但没有指定覆盖");
			return -1;
		}
		if (!((palerain_flags & palerain_option_pongo_exit) || (palerain_flags & palerain_option_pongo_exit)))
		{
#ifdef NO_KPF
			if (checkra1n_kpf_pongo_lzma_len == 0)
			{
				LOG(LOG_FATAL, "内核补丁程序在构建中省略，但没有指定覆盖");
				return -1;
			}
#endif
		}
#endif

#ifdef NO_EMBED_HELPER
	if (libcheckra1nhelper_dylib_len == 0 && gOverrideLibcheckra1nHelper == NULL) {
			LOG(LOG_FATAL, "构建中省略了checkra1n帮助器，但没有指定覆盖");
			return -1;
	}
#endif
	}

	for (index = optind; index < argc; index++)
	{
		if (!strcmp("windows", argv[index]))
		{
			fprintf(stderr,
					"Windows not really using for manipulating OSX images,\n"
					"compiled in mingw tool for this working unstable and incorrectly\n");
			return -2;
		}
		else
		{
			fprintf(stderr, "%s: 未知参数: %s\n", argv[0], argv[index]);
			usage(1, argv[0]);
		}
	}
	if (verbose >= 2) setenv("LIBUSB_DEBUG", "1", 1);

	if (verbose >= 3)
	{
		libusbmuxd_set_debug_level(verbose - 2);
		irecv_set_debug_level(1);
		setenv("LIBUSB_DEBUG", "2", 1);
	}
	if (verbose >= 4) {
		idevice_set_debug_level(1);
		setenv("LIBUSB_DEBUG", "3", 1);
	}
	if (verbose >= 5)
		setenv("LIBUSB_DEBUG", "4", 1);
    return 0;
}
