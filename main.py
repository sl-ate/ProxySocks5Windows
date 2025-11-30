import asyncio
import struct
import socket
import logging
import subprocess
import ctypes
import sys
import os

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [%(levelname)s] - %(message)s'
)
logger = logging.getLogger(__name__)

# Server Configuration
HOST = '0.0.0.0'
PORT = 1080

def is_admin():
    """Check if the script is running with administrative privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def setup_firewall(port):
    """Automatically adds a firewall rule for the specified port."""
    rule_name = "Python SOCKS5 Proxy"
    
    if not is_admin():
        logger.warning("Not running as Administrator. Cannot configure firewall automatically.")
        logger.warning("Please run this script as Administrator or configure firewall manually.")
        return

    try:
        # Check if rule already exists
        check_cmd = f'netsh advfirewall firewall show rule name="{rule_name}"'
        result = subprocess.run(check_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        
        if result.returncode == 0:
            logger.info(f"Firewall rule '{rule_name}' already exists.")
            return

        # Add the rule if it doesn't exist
        logger.info(f"Adding firewall rule for port {port}...")
        add_cmd = (
            f'netsh advfirewall firewall add rule name="{rule_name}" '
            f'dir=in action=allow protocol=TCP localport={port}'
        )
        subprocess.run(add_cmd, shell=True, check=True, stdout=subprocess.PIPE)
        logger.info(f"Successfully added firewall rule: Allow TCP {port}")

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to add firewall rule: {e}")
    except Exception as e:
        logger.error(f"Unexpected error configuring firewall: {e}")

async def handle_client(reader, writer):
    """Handles the incoming client connection."""
    client_addr = writer.get_extra_info('peername')
    
    try:
        # Step 1: Handshake
        header = await reader.read(2)
        if not header: return

        version, nmethods = struct.unpack("!BB", header)
        if version != 5:
            writer.close()
            return

        await reader.read(nmethods)
        writer.write(b'\x05\x00')
        await writer.drain()

        # Step 2: Request
        header = await reader.read(4)
        if not header: return
        ver, cmd, rsv, atyp = struct.unpack("!BBBB", header)

        if cmd != 1:
            reply = b'\x05\x07\x00\x01' + b'\x00' * 6
            writer.write(reply)
            await writer.drain()
            writer.close()
            return

        remote_addr = None
        if atyp == 1:
            addr_bytes = await reader.read(4)
            remote_addr = socket.inet_ntoa(addr_bytes)
        elif atyp == 3:
            addr_len = (await reader.read(1))[0]
            remote_addr = (await reader.read(addr_len)).decode()
        elif atyp == 4:
            addr_bytes = await reader.read(16)
            remote_addr = socket.inet_ntop(socket.AF_INET6, addr_bytes)
        
        port_bytes = await reader.read(2)
        remote_port = struct.unpack("!H", port_bytes)[0]

        logger.info(f"Connecting {client_addr} -> {remote_addr}:{remote_port}")

        # Step 3: Connect
        try:
            remote_reader, remote_writer = await asyncio.open_connection(remote_addr, remote_port)
        except Exception as e:
            logger.error(f"Connection failed: {e}")
            reply = b'\x05\x05\x00\x01' + b'\x00' * 6
            writer.write(reply)
            writer.close()
            return

        reply = b'\x05\x00\x00\x01' + socket.inet_aton('0.0.0.0') + struct.pack("!H", 0)
        writer.write(reply)
        await writer.drain()

        # Step 4: Relay
        await relay_data(reader, writer, remote_reader, remote_writer)

    except Exception as e:
        logger.error(f"Error: {e}")
    finally:
        writer.close()

async def relay_data(client_reader, client_writer, remote_reader, remote_writer):
    async def forward(src, dst):
        try:
            while True:
                data = await src.read(4096)
                if not data: break
                dst.write(data)
                await dst.drain()
        except: pass
        finally: dst.close()

    await asyncio.gather(
        forward(client_reader, remote_writer),
        forward(remote_reader, client_writer)
    )

async def main():
    # Setup firewall before starting the server
    setup_firewall(PORT)

    server = await asyncio.start_server(handle_client, HOST, PORT)
    addr = server.sockets[0].getsockname()
    logger.info(f'SOCKS5 Proxy running on {addr}')
    
    async with server:
        await server.serve_forever()

if __name__ == '__main__':
    # Attempt to elevate to admin if needed for firewall changes
    if not is_admin():
        print("Script is not running as Administrator.")
        print("Trying to restart with Admin privileges to configure Firewall...")
        try:
            # Re-run the script with Admin rights
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, " ".join(sys.argv), None, 1
            )
            # Exit this instance, the new admin instance will take over
            sys.exit()
        except Exception as e:
            print(f"Failed to elevate: {e}")
            print("Running without auto-firewall configuration.")
    
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer stopped.")
