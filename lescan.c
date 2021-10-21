#include <stdint.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <bluetooth/bluetooth.h>
#include <bluetooth/hci.h>
#include <bluetooth/hci_lib.h>

#include <stdio.h>

typedef enum
{
	BLE_ADDRESS_PUBLIC = LE_PUBLIC_ADDRESS,
	BLE_ADDRESS_RANDOM = LE_RANDOM_ADDRESS
} ble_address_type_t;

typedef enum
{
	BLE_SCAN_TYPE_PASSIVE = 0x00,
	BLE_SCAN_TYPE_ACTIVE  = 0x01
} ble_scan_type_t;

typedef enum 
{
       BLE_SCAN_DUPLICATES_OFF = 0x00,
       BLE_SCAN_DUPLICATES_ON  = 0x01
} ble_scan_duplicates_t;

typedef enum 
{
	BLE_SCAN_ENABLE_OFF = 0x00,
	BLE_SCAN_ENABLE_ON  = 0x01
} ble_scan_enable_t;

typedef enum
{
	BLE_EIR_NAME_SHORT    = 0x08,
	BLE_EIR_NAME_COMPLETE = 0x09
} ble_eir_name_t;

static uint8_t cmd_lescan(int dev_id);
static uint8_t print_advertising_devices(int dd, uint8_t scan_timeout_sec);
void sigint_handler(int sig);
static void eir_parse_name(uint8_t *eir, size_t eir_len, char *buf, size_t buf_len);
double get_wall_time();


static volatile int signal_received = 0;

int main()
{
	cmd_lescan(0 /* hci0 */);

	return 0;
}

uint8_t print_advertising_devices(int dd, uint8_t scan_timeout_sec)
{
	unsigned char buf[HCI_MAX_EVENT_SIZE], *ptr;
	struct hci_filter nf, of;
	struct sigaction sa;
	socklen_t olen;
	int len;
	
	fd_set descriptor_set;
	struct timeval timeout;

	olen = sizeof(of);
	if (getsockopt(dd, SOL_HCI, HCI_FILTER, &of, &olen) < 0) {
		return 1;
	}

	hci_filter_clear(&nf);
	hci_filter_set_ptype(HCI_EVENT_PKT, &nf);
	hci_filter_set_event(EVT_LE_META_EVENT, &nf);

	if (setsockopt(dd, SOL_HCI, HCI_FILTER, &nf, sizeof(nf)) < 0) {
		return 2;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_NOCLDSTOP;
	sa.sa_handler = sigint_handler;
	sigaction(SIGINT, &sa, NULL);
	
	double scan_start_time = get_wall_time();	
	double age = 0;
	
	while ((double)scan_timeout_sec > (age=(get_wall_time()-scan_start_time)))
	{
		evt_le_meta_event *meta;
		le_advertising_info *info;
		char addr[18];
		
		int res = 0;

		//Wait for 1sec in read() and then loop again
		timeout.tv_sec = 1;
		timeout.tv_usec = 0;
		
		FD_ZERO(&descriptor_set);
		FD_SET(dd, &descriptor_set);
	
		if (1 == (res = select(dd + 1, &descriptor_set, NULL, NULL, &timeout)))
		{
			len = read(dd, buf, sizeof(buf));
			if (errno == EINTR && signal_received == SIGINT)
			{
				return 0;
			}
			
			ptr = buf + (1 + HCI_EVENT_HDR_SIZE);
			len -= (1 + HCI_EVENT_HDR_SIZE);

			meta = (void *) ptr;

			if (meta->subevent != 0x02)
				return 0;

			/* Ignoring multiple reports */
			info = (le_advertising_info *) (meta->data + 1);

			char name[128];

			memset(name, 0, sizeof(name));

			ba2str(&info->bdaddr, addr);
			eir_parse_name(info->data, info->length,
							name, sizeof(name) - 1);

			printf("%s %s\n", addr, name);
		}
		else if (res < 0)
		{
			// Error occured
			return 1;
		}
	}

	setsockopt(dd, SOL_HCI, HCI_FILTER, &of, sizeof(of));

	return 0;
}


uint8_t cmd_lescan(int dev_id)
{
	int err, opt, dd;
	ble_address_type_t address_type = BLE_ADDRESS_PUBLIC;
	ble_scan_type_t scan_type = BLE_SCAN_TYPE_ACTIVE;
	ble_scan_duplicates_t filter_dup = BLE_SCAN_DUPLICATES_ON;
	uint16_t command_timeout_ms = 10000;
	uint16_t scan_timeout_sec= 10;

	uint8_t filter_policy = 0x00;
	uint16_t interval = htobs(0x0010);  // defined as the time interval from the last LE scan until it begins the subsequent LE scan.
	uint16_t window = htobs(0x0010);    // the duration of the LE scan. When interval = duration, we scan non stop

	if (dev_id < 0)
		dev_id = hci_get_route(NULL);

	dd = hci_open_dev(dev_id);
	if (dd < 0)
	{
		return 1;
	}

	// Try to close scanning session if it was still opened from before
	err = hci_le_set_scan_enable(dd, BLE_SCAN_ENABLE_OFF, filter_dup, command_timeout_ms);

	err = hci_le_set_scan_parameters(dd, scan_type, interval, window,
		address_type, filter_policy, command_timeout_ms);
	if (err < 0)
	{
		return 2;
	}

	err = hci_le_set_scan_enable(dd, BLE_SCAN_ENABLE_ON, filter_dup, command_timeout_ms);
	if (err < 0)
	{
		return 3;
	}

	printf("LE Scan ...\n");
	
	err = print_advertising_devices(dd, scan_timeout_sec);
	
	if (err != 0)
	{
		return 4;
	}

	printf("LE Scan finished\n");
	
	err = hci_le_set_scan_enable(dd, BLE_SCAN_ENABLE_OFF, filter_dup, command_timeout_ms);
	if (err < 0)
	{
		return 5;
	}

	hci_close_dev(dd);
	
	return 0;
}

void sigint_handler(int sig)
{
	signal_received = sig;
}

void eir_parse_name(uint8_t *eir, size_t eir_len, char *buf, size_t buf_len)
{
	size_t offset;

	offset = 0;
	while (offset < eir_len) {
		uint8_t field_len = eir[0];
		size_t name_len;

		/* Check for the end of EIR */
		if (field_len == 0)
			break;

		if (offset + field_len > eir_len)
			goto failed;

		switch (eir[1]) {
		case BLE_EIR_NAME_SHORT:
		case BLE_EIR_NAME_COMPLETE:
			name_len = field_len - 1;
			if (name_len > buf_len)
				goto failed;

			memcpy(buf, &eir[2], name_len);
			return;
		}

		offset += field_len + 1;
		eir += field_len + 1;
	}

failed:
	snprintf(buf, buf_len, "(unknown)");
}

double get_wall_time()
{
    struct timeval time;
    if (gettimeofday(&time,NULL)){
        //  Handle error
        return 0;
    }
    return (double)time.tv_sec + (double)time.tv_usec * .000001;
}
