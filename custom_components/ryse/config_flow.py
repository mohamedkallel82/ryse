from homeassistant import config_entries
import voluptuous as vol
import logging
from bleak import BleakScanner, BleakClient
import subprocess
import asyncio

_LOGGER = logging.getLogger(__name__)

DOMAIN = "ryse"
PAIRING_MODE_FLAG = 0x01  # LE Limited Discoverable Mode (standard pairing mode)

# Hardcoded UUIDs
HARDCODED_UUIDS = {
    "rx_uuid": "a72f2801-b0bd-498b-b4cd-4a3901388238",
    "tx_uuid": "a72f2802-b0bd-498b-b4cd-4a3901388238",
}

def close_process(process):
    process.stdin.close()
    process.stdout.close()
    process.stderr.close()
    process.wait()

class RyseBLEDeviceConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for RYSE BLE Device."""

    VERSION = 1

    async def async_step_user(self, user_input=None):
        """Handle the initial step."""
        if user_input is not None:
            return await self.async_step_scan()

        # Show confirmation popup
        return self.async_show_form(
            step_id="user",
            description_placeholders={"info": "Press OK to start scanning for RYSE BLE devices."},
            data_schema=vol.Schema({}),  # Empty schema means no input field
            last_step=False,
        )

    async def async_step_scan(self, user_input=None):
        """Handle the BLE device scanning step."""
        if user_input is not None:
            # Extract device name and address from the selected option
            selected_device = next(
                (name for addr, name in self.device_options.items() if addr == user_input["device_address"]),
                None,
            )
            if not selected_device:
                return self.async_abort(reason="Invalid selected device!")
            
            device_name = selected_device.split(" (")[0]  # Extract device name before "("
            device_address = user_input["device_address"]

            try:
                _LOGGER.debug("Attempting to pair with BLE device: %s (%s)", device_name, device_address)

                command = ["bluetoothctl", "trust", device_address]
                result = subprocess.run(command, capture_output=True, text=True, check=True)
                # Start bluetoothctl in interactive mode
                process = subprocess.Popen(
                    ["bluetoothctl"],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    bufsize=1
                )

                max_retries = 3
                retry_count = 0
                while retry_count < max_retries:
                    try:
                        client = BleakClient(device_address)
                        await client.connect()
                        if client.is_connected:
                            _LOGGER.debug(f"Connected to {device_address}")

                            # Pairing (Only required if your device needs pairing)
                            try:
                                paired = await client.pair()
                                if not paired:
                                    _LOGGER.error("Failed to pair with BLE device: %s (%s)", device_name, device_address)
                                    close_process(process)
                                    return self.async_abort(reason="Pairing failed!")
                                else:
                                    _LOGGER.debug("Paired successfully")
                                    break  # Exit the retry loop on success
                            except Exception as e:
                                _LOGGER.warning(f"Pairing failed: {e}")
                        else:
                            _LOGGER.error("Failed to connect")
                            close_process(process)
                            return False
                    except Exception as e:
                        _LOGGER.error(f"Connection error (attempt {retry_count + 1}): {e}")
                        retry_count += 1
                        if retry_count >= max_retries:
                            close_process(process)
                            return False
                        await asyncio.sleep(3)  # Wait before retrying

                await asyncio.sleep(5)
                close_process(process)

                _LOGGER.debug("Successfully paired with BLE device: %s (%s)", device_name, device_address)

                # Create entry after successful pairing
                return self.async_create_entry(
                    title=f"RYSE gear {device_name}",
                    data={
                        "address": device_address,
                        **HARDCODED_UUIDS,
                    },
                )

            except Exception as e:
                _LOGGER.error("Error during pairing process for BLE device: %s (%s): %s", device_name, device_address, e)
                return self.async_abort(reason="Pairing failed!")

        # Scan for BLE devices
        devices = await BleakScanner.discover()

        # Debug: Log all discovered devices
        for device in devices:
            _LOGGER.debug("Device Name: %s - Device Address: %s", device.name, device.address)

        # Get existing entries to exclude already configured devices
        existing_entries = self._async_current_entries()
        existing_addresses = {entry.data["address"] for entry in existing_entries}

        self.device_options = {}

        for device in devices:
            if not device.name:
                continue  # Ignore unnamed devices
            if device.address in existing_addresses:
                _LOGGER.debug("Skipping already configured device: %s (%s)", device.name, device.address)
                continue  # Skip already configured devices

            manufacturer_data = device.metadata.get("manufacturer_data", {})
            raw_data = manufacturer_data.get(0x0409)  # 0x0409 == 1033
            if raw_data != None:
                _LOGGER.debug("Found RYSE Device in Pairing mode: %s - address: %s", device.name, device.address)
                # Check if the pairing mode flag (0x40) is in the first byte
                if len(raw_data) > 0 and (raw_data[0] & 0x40):
                    self.device_options[device.address] = f"{device.name} ({device.address})"

        if not self.device_options:
            _LOGGER.warning("No BLE devices found in pairing mode (0x40).")
            return self.async_abort(reason="No RYSE devices found in pairing mode!")

        # Show device selection form
        return self.async_show_form(
            step_id="scan",
            data_schema=vol.Schema(
                {
                    vol.Required("device_address"): vol.In(self.device_options),
                }
            ),
            description_placeholders={"info": "Select a RYSE BLE device to pair."}
        )