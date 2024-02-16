import subprocess
import re
import matplotlib.pyplot as plt
import time

def get_packet_drops(interface):
    # Run tc qdisc show command to get packet drops
    output = subprocess.check_output(['tc', '-s', 'qdisc', 'show', 'dev', interface]).decode('utf-8')
    
    # Extract packet drops from output using regular expression
    match = re.search(r'backlog\s+\d+b\s+\d+p\s+\d+d\s+(\d+)c', output)
    if match:
        return int(match.group(1))
    else:
        return 0

def visualize_packet_drops(interface, interval=1, duration=10):
    # Initialize lists to store data for plotting
    time_points = []
    packet_drops = []
    # Collect data for the specified duration
    for i in range(duration):
        time_points.append(i * interval)
        packet_drops.append(get_packet_drops(interface))
        time.sleep(interval)

    # Print collected data
    print("Time points:", time_points)
    print("Packet drops:", packet_drops)

    # Plot packet drops over time
    plt.plot(time_points, packet_drops, marker='o')
    plt.xlabel('Time (seconds)')
    plt.ylabel('Packet Drops')
    plt.title('Packet Drops over Time')
    plt.grid(True)
    plt.show()

if __name__ == '__main__':
    interface = 'ens33'  # Replace with the name of your network interface
    visualize_packet_drops(interface)
