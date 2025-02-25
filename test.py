import dotenv
import ewelink

# Load config
config = dotenv.dotenv_values()
client_id = config.get("client_id", None)
client_secret = config.get("client_secret", None)
email = config.get("email", None)
password = config.get("password", None)
redirect_url = config.get("redirect_url", None)
region = config.get("region", None)

# Initialize eWeLink
ewl = ewelink.EWeLink(
    client_id=client_id,
    client_secret=client_secret,
    region=region
)

# Authenticate
data = ewl.ng_oauth(email=email, password=password, redirect_url=redirect_url)
tokens = ewl.token(code=data["data"]["code"], redirect_url=redirect_url)

# Get devices
devices = ewl.get_devices()
#print("Devices:", json.dumps(devices, indent=2))

# Select Device
device_id = devices.get("data", {}).get("thingList", [{}])[0].get("itemData", {}).get("deviceid")
if not device_id:
    print("❌ No devices found!")
    exit()

print(f"✅ Using Device ID: {device_id}")

# @ewl.event
# async def on_before_start(ctx :ewelink.WebsocketOnBeforeStart):
#     print(ctx.__dict__)

# @ewl.event
# async def on_websocket_ping(ctx :ewelink.WebsocketPing):
#     print(ctx.__dict__)

# Function to control the device
@ewl.event
async def on_websocket(ctx :ewelink.WebsocketOnStart):
    await ewl.send_handshake()
    while True:
        action = input("Enter command (on/off/status/exit): ").strip().lower()
        outlet = 0
        if action == "on":
            await ewl.set_query_device(device_id, {
                "switches": [
                    {
                        "switch": "on",
                        "outlet": outlet
                    }
                ]
            })
            print("✅ Turned ON")
        elif action == "off":
            await ewl.set_query_device(device_id, {
                "switches": [
                    {
                        "switch": "off",
                        "outlet": outlet
                    }
                ]
            })
            print("✅ Turned OFF")
        elif action == "status":
            response = await ewl.get_query_device(device_id)
            print(f"📊 Device Status: {response["params"]["switches"][outlet]["switch"].upper()}")
        elif action == "exit":
            print("👋 Exiting...")
            break
        else:
            print("❌ Invalid command. Use 'on', 'off', 'status', or 'exit'.")

ewl.run()