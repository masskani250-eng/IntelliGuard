import psutil

print("\n=== INTELLIGUARD APPLICATION CONNECTION TEST ===\n")

found = 0

for conn in psutil.net_connections(kind="inet"):
    try:
        if not conn.pid:
            continue

        process = psutil.Process(conn.pid)
        process_name = process.name()

        local = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "-"
        remote = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "-"

        print(f"APP: {process_name}")
        print(f"PID: {conn.pid}")
        print(f"LOCAL: {local}")
        print(f"REMOTE: {remote}")
        print("-" * 50)

        found += 1

        if found >= 20:
            break

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        continue

print(f"\nConnections detected: {found}")