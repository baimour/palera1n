#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdbool.h>
#include <unistd.h>
#include <ctype.h>

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>
#include <inttypes.h>

#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/diagnostics_relay.h>
#include <plist/plist.h>
#include <libirecovery.h>
#include <usbmuxd.h>

#include <ANSI-color-codes.h>
#include <palerain.h>

#define FORMAT_KEY_VALUE 1
#define FORMAT_XML 2

#define NO_PHYSICAL_HOME_BUTTON (cpid == 0x8015 || (cpid == 0x8010 && (bdid == 0x08 || bdid == 0x0a || bdid == 0x0c || bdid == 0x0e)))
#define IS_APPLE_TV_HD (cpid == 0x7000 && bdid == 0x34)
#define IS_APPLE_TV_4K (cpid == 0x8011 && bdid == 0x02)
#define IS_APPLE_HOME1 (cpid == 0x7000 && bdid == 0x38)
#define IS_APPLE_HOME2 (cpid == 0x7000 && bdid == 0x1a)
#define IS_APPLE_HOME  (IS_APPLE_HOME1 || IS_APPLE_HOME1)
#define IS_APPLETV (IS_APPLE_TV_4K || IS_APPLE_TV_HD || IS_APPLE_HOME)

int dfuhelper_thr_running = false;

static void step(int time, int time2, char *text, bool (*cond)(uint64_t), uint64_t cond_arg) {
    for (int i = time2; i < time; i++) {
		printf(
			(palerain_flags & palerain_option_no_colors) 
			? "\r\033[K%s (%d)" 
			: BCYN "\r\033[K%s (%d)" CRESET, text, time - i + time2
		);
        fflush(stdout);
        sleep(1);
		if (cond != NULL && cond(cond_arg)) pthread_exit(NULL);
    }
    printf(
		(palerain_flags & palerain_option_no_colors)
		? "\r%s (%d)" 
		: CYN "\r%s (%d)" CRESET, text, time2
	);
	if (time2 == 0) puts("");
}

static int connected_normal_mode(const usbmuxd_device_info_t *usbmuxd_device) {
	devinfo_t dev;
	int ret;
	ret = devinfo_cmd(&dev, usbmuxd_device->udid);
	if (ret != 0) {
		LOG(LOG_ERROR, "无法获取设备信息");
		return 0;
	}
	if (strcmp(dev.CPUArchitecture, "arm64")) {
		devinfo_free(&dev);
		LOG(LOG_WARNING, "忽略non-arm64设备...");
		LOG(LOG_WARNING, "palera1n不支持A12+，也永远不会支持 (arm64e)");
		return -1;
	}

	if ((palerain_flags & palerain_option_device_info)) {
		printf("模式: 正常\n");
		printf("产品类型: %s\n", dev.productType);
		printf("架构: %s\n", dev.CPUArchitecture);
		printf("版本: %s\n", dev.productVersion);
		printf("显示名称: %s\n", dev.displayName);

		device_has_booted = true;
		set_spin(0);
		unsubscribe_cmd();
		return 0;
	}

	/* For Booting Linux etc */
	if (!getenv("PALERA1N_BYPASS_PASSCODE_CHECK") &&
		!strncmp(dev.productType, "iPhone10,", strlen("iPhone10,")
		)) {
		if (!(palerain_flags & palerain_option_device_info))
			LOG(LOG_VERBOSE2, "设备%s需要禁用密码", dev.productType);
		unsigned char passcode_state = 0;
		ret = passstat_cmd(&passcode_state, usbmuxd_device->udid);
		if (ret != 0) {
			LOG(LOG_ERROR, "无法获取密码状态");
			devinfo_free(&dev);
			return -1;
		}
		if (passcode_state) {
			LOG(LOG_ERROR, "必须在此设备上禁用密码");
			if (!(palerain_flags & palerain_option_device_info))
				LOG(LOG_ERROR, "此外，在iOS 16+上恢复后，绝不能设置密码");
			devinfo_free(&dev);
			return -1;
		}
	}
	
	if (getenv("PALERA1N_BYPASS_PASSCODE_CHECK"))
		LOG(LOG_WARNING, "绕过密码检查");	

	if (verbose > 1) {
		/* (LOG_VERBOSE - 3) or below*/
		LOG(LOG_INFO, "正在让UDID为%s的设备进入恢复模式", usbmuxd_device->udid);
	} else {
		/* At least (LOG_VERBOSE2 - 3) */
		LOG(LOG_INFO, "正在进入恢复模式");
	}
	enter_recovery_cmd(usbmuxd_device->udid);
	devinfo_free(&dev);
	if ((palerain_flags & palerain_option_enter_recovery)) {
		device_has_booted = true;
		set_spin(0);
		unsubscribe_cmd();
	}
	return 0;
}

static bool conditional(uint64_t ecid) {
	return get_ecid_wait_for_dfu() != ecid;
}

static void* connected_recovery_mode(struct irecv_device_info* info) {
	int ret;
	uint64_t ecid;
	uint32_t cpid, bdid;
	cpid = info->cpid;
	ecid = info->ecid;
	bdid = info->bdid;
	info = NULL;
	if (!cpid_is_arm64(cpid)) {
		LOG(LOG_WARNING, "忽略non-arm64设备...");
		return NULL;
	}
	sleep(1);
	ret = autoboot_cmd(ecid);
	if (ret) {
		LOG(LOG_ERROR, "无法将auto-boot恢复为true");
		return NULL;
	}
#if !defined(DFUHELPER_AUTO_ONLY)
	if (IS_APPLE_TV_4K) {
		LOG(LOG_INFO, "根据您的连接方式，在重新启动期间，您可能需要按下电缆/板上的按钮");
	}
	LOG(LOG_INFO, "准备好进入DFU模式时，请按Enter键");
	getchar();
#endif
	if (IS_APPLETV) {
		if (IS_APPLE_TV_HD) {
			step(10, 8, "按住电源键+音量减按钮", NULL, 0);
			set_ecid_wait_for_dfu(ecid);
			ret = exitrecv_cmd(ecid);
			if (ret) {
				LOG(LOG_ERROR, "无法退出恢复模式");
				set_ecid_wait_for_dfu(0);
				return NULL;
			}
			printf("\r\033[K");
			step(8, 0, "按住电源键+音量减按钮", conditional, ecid);
		} else if (IS_APPLE_TV_4K) {
			step(2, 0, "即将重启设备", NULL, 0);
			set_ecid_wait_for_dfu(ecid);
			ret = exitrecv_cmd(ecid);
			if (ret) {
				LOG(LOG_ERROR, "无法退出恢复模式");
				set_ecid_wait_for_dfu(0);
				return NULL;
			}
			step(4, 0, "等待设备在DFU模式下重新连接", conditional, ecid);
		} else if (IS_APPLE_HOME) {
			step(6, 4, "将设备以倒置访问放置", NULL, 0);
			set_ecid_wait_for_dfu(ecid);
			ret = exitrecv_cmd(ecid);
			if (ret) {
				LOG(LOG_ERROR, "无法退出恢复模式");
				set_ecid_wait_for_dfu(0);
				return NULL;
			}
			step(4, 0, "将设备以倒置方向放置", conditional, ecid);
		}
	} else if (cpid != 0x8012) {
		if (NO_PHYSICAL_HOME_BUTTON)
			step(4, 2, "按住音量减 + 电源键按钮", NULL, 0);
		else
			step(4, 2, "按住Home键+电源键按钮", NULL, 0);
		set_ecid_wait_for_dfu(ecid);
		ret = exitrecv_cmd(ecid);
		if (ret) {
			LOG(LOG_ERROR, "无法退出恢复模式");
			set_ecid_wait_for_dfu(0);
			return NULL;
		}
		printf("\r\033[K");
		if (NO_PHYSICAL_HOME_BUTTON) {
			step(2, 0, "按住音量减 + 电源键按钮", NULL, 0);
			step(10, 0, "按住音量减按钮", conditional, ecid);
		} else {
			step(2, 0, "按住Home键+电源键按钮", NULL, 0);
			step(10, 0, "按住Home键", conditional, ecid);
		}
	}
	if (get_ecid_wait_for_dfu() == ecid) {
		LOG(LOG_WARNING, "哎呀，设备没有进入DFU模式");
		LOG(LOG_INFO, "等待设备重新连接...");
		set_ecid_wait_for_dfu(0);
		return NULL;
	}
	set_ecid_wait_for_dfu(0);
	pthread_exit(NULL);
	return NULL;
}

static void* connected_dfu_mode(struct irecv_device_info* info) {
	if (get_ecid_wait_for_dfu() == info->ecid) {
		set_ecid_wait_for_dfu(0);
		puts("");
		LOG(LOG_INFO, "设备成功进入 DFU 模式");
	}
	unsigned int bdid = info->bdid;
	unsigned int cpid = info->cpid;
	if (IS_APPLE_HOME) {
		step(2, 0, "将设备直立放置", NULL, 0);
	}
	set_spin(0);
	unsubscribe_cmd();
	pthread_exit(NULL);
	return NULL;
}

static void device_event_cb(const usbmuxd_event_t *event, void* userdata) {
	if (event->device.conn_type != CONNECTION_TYPE_USB) return;
	switch (event->event) {
	case UE_DEVICE_ADD:
		LOG(LOG_VERBOSE, "在正常模式下设备已连接");
		if ((palerain_flags & palerain_option_exit_recovery)) {
			break;
		} else if ((palerain_flags & palerain_option_reboot_device)) {
			int ret = reboot_cmd(event->device.udid);
			if (!ret) {
				LOG(LOG_INFO, "已重新启动设备");
				set_spin(0);
				unsubscribe_cmd();
			}
			pthread_exit(NULL);
			break;
		}
		connected_normal_mode(&event->device);
		break;
	case UE_DEVICE_REMOVE:
		LOG(LOG_VERBOSE, "正常模式设备已断开连接");
		break;
	}
}

static void irecv_device_event_cb(const irecv_device_event_t *event, void* userdata) {
	pthread_t recovery_thread, dfu_thread;
	int ret;
	
	switch(event->type) {
		case IRECV_DEVICE_ADD:
			if (event->mode == IRECV_K_RECOVERY_MODE_1 || 
				event->mode == IRECV_K_RECOVERY_MODE_2 || 
				event->mode == IRECV_K_RECOVERY_MODE_3 || 
				event->mode == IRECV_K_RECOVERY_MODE_4) {
				if (!(palerain_flags & palerain_option_device_info))
					LOG(LOG_VERBOSE, "恢复模式设备: %" PRIu64 " 已连接", event->device_info->ecid);
				if ((palerain_flags & palerain_option_exit_recovery)) {
					ret = exitrecv_cmd(event->device_info->ecid);
					if (!ret) {
						LOG(LOG_INFO, "退出恢复模式");
						device_has_booted = true;
						set_spin(0);
						unsubscribe_cmd();
					} else {
						LOG(LOG_WARNING, "无法退出恢复模式");
					}
					if (dfuhelper_thr_running) pthread_cancel(dfuhelper_thread);
					pthread_exit(NULL);
					break;
				}

				if ((palerain_flags & palerain_option_device_info)) {
					recvinfo_t info;
					ret = recvinfo_cmd(&info, event->device_info->ecid);
					if (ret) {
						LOG(LOG_WARNING, "无法从设备获取信息");
					} else {
						printf("模式: 恢复模式\n");
						printf("产品类型: %s\n", info.product_type);
						printf("显示名称: %s\n", info.display_name);

						device_has_booted = true;
						set_spin(0);
						unsubscribe_cmd();
					}
					if (dfuhelper_thr_running) pthread_cancel(dfuhelper_thread);
					pthread_exit(NULL);
					break;
				}

				if ((palerain_flags & palerain_option_enter_recovery) ||
					(palerain_flags & palerain_option_reboot_device)) return;
				pthread_create(&recovery_thread, NULL, (pthread_start_t)connected_recovery_mode, event->device_info);
			} else if (event->mode == IRECV_K_DFU_MODE) {
				if (!(palerain_flags & palerain_option_device_info))
					LOG(LOG_VERBOSE, "DFU模式设备: %" PRIu64 " 已连接", event->device_info->ecid);

				if ((palerain_flags & palerain_option_device_info)) {
					recvinfo_t info;
					ret = recvinfo_cmd(&info, event->device_info->ecid);
					if (ret) {
						LOG(LOG_WARNING, "无法从设备获取信息");
					} else {
						printf("模式: DFU模式\n");
						printf("产品类型: %s\n", info.product_type);
						printf("显示名称: %s\n", info.display_name);

						device_has_booted = true;
						set_spin(0);
						unsubscribe_cmd();
					}
					if (dfuhelper_thr_running) pthread_cancel(dfuhelper_thread);
					pthread_exit(NULL);
					break;
				}

				if (
					(palerain_flags & palerain_option_exit_recovery) ||
					(palerain_flags & palerain_option_enter_recovery) ||
					(palerain_flags & palerain_option_reboot_device)) {
						break;
				}
				pthread_create(&dfu_thread, NULL, (pthread_start_t)connected_dfu_mode, event->device_info);
			}
			break;
		case IRECV_DEVICE_REMOVE:
			LOG(LOG_VERBOSE, "恢复模式设备已断开连接");
		break;
	}
}

void *dfuhelper(void* ptr) {
	dfuhelper_thr_running = true;
	set_spin(1);
	subscribe_cmd(device_event_cb, irecv_device_event_cb);
	while (get_spin()) {
		sleep(1);
	};
	dfuhelper_thr_running = false;
	return 0;
}
