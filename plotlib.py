# ....DROUGKA SOFIA ....#
# ....Program to Analyze Network Behavior through CSV exported pcap Files.... #
# ....Developed in the context the Master thesis....#
# ....In Athens University of Economics and Business....#

# This software plots the diagrams derived from the results which have been calculated
# by the experiments conducted in the CORE Virtual Machine (COREVM)
import numpy as np
from matplotlib import pyplot as plt, axes

data_none = None
data_1_3 = [1.139811, 0.060604, 0.25255, 0.070723, 0.056036, 0.61252, 1.621841, 0.080613, 0.178987]
data_4_8 = [0.051104, 0.067538, 0.042186, 0.046949, 0.043018, 0.096948, 0.092334, data_none, data_none]

data_conv_2_throughput = [12907.597, 9995.377, 24266.882, 30259.391]
data_rnd2_throughput = [15711.881, 14407.124, 15401.798, 14085.344]
data_conv_10_throughput = [12367.390, 8638.976, 14734.138, 20458.024]
data_rnd10_throughput = [11855.627, 11203.310, 21546.439, 22448.323]
conv2_delay = [0.342, 0.330, 0.380, 0.384]
rnd2_delay = [0.367, 0.333, 1.174, 0.413]
conv2_packet_loss = [12, 2, 5, 2]
rnd2_packet_loss = [38, 32, 70, 16]
conv2_pdr = [14.634, 4.762, 7.692, 1.087]
rnd2_pdr = [15.638, 13.333, 13.672, 10.390]
conv10_delay = [0.313, 0.333, 0.315, 0.438]
rnd10_delay = [0.334, 0.326, 0.425, 6.264]
con10_packet_loss = [27, 473, 105, 63]
rnd10_packet_loss = [25, 23, 92, 43]
conv10_pdr = [3.539, 49.016, 15.239, 7.119]
rnd10_pdr = [4.006, 3.758, 10.155, 2.532]


# STATIC NETWORK: 1 to 3 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES
# PLOT DIAGRAM IN LINE DESIGN
def static_delay_1_3_hops_line():
    # Results from the calculation of delay in the experiments of static network in 1 to 3 hops case
    static_delay_1_3 = [0.178987, 0.519360286, 0.080613]
    x_axis_1_1_3_delay = ['1', '3', '4']
    line1 = plt.plot(x_axis_1_1_3_delay, static_delay_1_3, 'bo-', label='line1')
    plt.legend(["1 to 3 hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number of Malicious Nodes")
    plt.grid()
    plt.show()

# STATIC NETWORK: 1 to 3 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES
# PLOT DIAGRAM IN BAR DESIGN
def static_delay_1_3_hops_bar():
    # Results from the calculation of delay in the experiments of static network in 1 to 3 hops case
    static_delay_1_3 = [0.0806130, 0.2193602, 0.478987]
    x_axis_1_1_3_delay = ['1', '3', '4']
    x_axis = [int(x) for x in x_axis_1_1_3_delay]
    c = ['red', 'yellow', 'black', 'blue', 'orange', 'green', 'grey', 'red']
    plt.bar(x_axis_1_1_3_delay, static_delay_1_3, width=0.4)
    plt.legend(["1 to 3 hops"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number Of Malicious Nodes In TCP SYN Flood Attack")
    plt.show()

# STATIC NETWORK: 4 to 8 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES
# PLOT DIAGRAM IN LINE DESIGN
def static_delay_4_8_hops_line():
    # Results from the calculation of delay in the experiments of static network in 1 to 3 hops case
    static_delay_4_8 = [0.047023667, 0.06023667, 0.096948]
    x_axis_1_4_8_delay = ['1', '2', '3']
    line1 = plt.plot(x_axis_1_4_8_delay, static_delay_4_8, 'ro-', label='line1')
    plt.legend(["4-8 hops"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number of Malicious Nodes ")
    plt.grid()
    plt.show()

# STATIC NETWORK: 1 to 3 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES
# PLOT DIAGRAM IN BAR DESIGN
def static_delay_4_8_hops_bar():
    # Results from the calculation of delay in the experiments of static network in 4 to 8 hops case
    static_delay_4_8 = [0.047023667, 0.096948, 0, 0]
    static_delay = [0.047023667, 0.096948]
    x_axis_1_4_8_delay = ['1', '2', '3', '4']
    x_axis = ['1', '2']
    x_axis = [int(x) for x in x_axis]
    z = np.polyfit(x_axis, static_delay, 2)
    p = np.poly1d(z)
    c = ['red', 'yellow', 'black', 'blue', 'orange', 'green', 'grey']
    plt.plot(x_axis, p(x_axis), 'ro-', label='line1')
    plt.bar(x_axis_1_4_8_delay, static_delay_4_8, width=0.4, color='orange')
    plt.legend(["Trend line", "4-8 hops"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number Of Malicious Nodes In TCP SYN Flood Attack")
    plt.show()

# STATIC NETWORK: 4 to 8 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES FOR TCP AND UDP FLOOD ATTACK
# PLOT DIAGRAM IN BAR DESIGN
def static_delay_4_8_hops_TCP_UDP_bar():
    static_delay_4_8_TCP = [0.047023667, 0.096948, 0, 0]
    static_delay_4_8_UDP = [0.055, 0.092, 0, 0]
    x_axis_1_4_8_delay = ['1', '2', '3', '4']
    X_axis = np.arange(len(x_axis_1_4_8_delay))
    c = ['red', 'yellow', 'black', 'blue', 'orange', 'green', 'grey']
    plt.bar(X_axis - 0.2, static_delay_4_8_TCP, 0.4)
    plt.bar(X_axis + 0.2, static_delay_4_8_UDP, 0.4)
    plt.xticks(X_axis, x_axis_1_4_8_delay)
    plt.legend(["TCP", "UDP"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number Of Malicious Nodes For 4-8 Hops \n In TCP SYN Flood Attack & UDP Flood Attack")
    plt.show()

# COMBINED DIAGRAM
# STATIC NETWORK: 4 to 8 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES FOR TCP SYN AND UDP FLOOD ATTACK
# PLOT DIAGRAM IN LINE DESIGN
def static_delay_13_48_hops_line():
    static_delay_1_3 = [0.519360286, 0.080613, 0.11567, 0.178987]
    static_delay_4_8 = [0.047023667, 0.096948, 0, 0]
    x_axis_1_1348_delay = ['1', '2', '3', '4']
    line1 = plt.plot(x_axis_1_1348_delay, static_delay_1_3, 'bo-', label='line1')
    line2 = plt.plot(x_axis_1_1348_delay, static_delay_4_8, 'ro-', label='line2')
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper right")
    plt.xlabel('Number of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number Of Malicious Nodes 1 - 3 and 4 - 8 Hops")
    plt.grid()
    plt.show()

# COMBINED DIAGRAM
# STATIC NETWORK: 1 TO 3  AND 4 to 8 Hops Case
# DELAY VS NUMBER OF MALICIOUS NODES FOR TCP SYN FLOOD ATTACK
# PLOT DIAGRAM IN BAR DESIGN
def static_delay_13_48_hops_bar():
    c = ['red', 'yellow', 'black', 'blue', 'orange', 'green', 'grey', 'blue']
    static_delay_1_3 = [0.0806130, 0, 0.2193602, 0.478987]
    static_delay_4_8 = [0.047023667, 0.096948, 0, 0]

    x_axis_1_1348_delay = ['1', '2', '3', '4']
    X_axis = np.arange(len(x_axis_1_1348_delay))

    plt.bar(X_axis - 0.2, static_delay_1_3, 0.4)
    plt.bar(X_axis + 0.2, static_delay_4_8, 0.4)

    plt.xticks(X_axis, x_axis_1_1348_delay)
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay vs Number Of Malicious Nodes For 1-3 & 4-8 Hops \n In TCP SYN Flood Attack")
    plt.show()


def static_1_3_tcp_throughput_line():
    throughput_1_3 = [74311.42046, 76144.19244, 146269.8973]
    x_axis_1_3_throughput = ['1', '3', '4']
    plt.plot(x_axis_1_3_throughput, throughput_1_3, 'ro-', label='line1')
    plt.legend(["1-3 Hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Throughput (Bytes/second)')
    plt.title("Throughput vs Number of Malicious Nodes 1 - 3 Hops TCP")
    plt.grid()
    plt.show()


def static_1_3_tcp_throughput_bar():
    throughput_1_3 = [74311.42046, 76144.19244, 146269.8973]
    x_axis_1_3_throughput = ['1', '3', '4']
    plt.bar(x_axis_1_3_throughput, throughput_1_3, width=0.4)
    plt.legend(["1-3 Hops"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Number Of Malicious Nodes For 1-3 Hops \n In TCP Syn Flood Attack")
    plt.show()


def static_4_8_tcp_throughput_line():
    throughput_4_8 = [25228.61028, 18994.88055]
    x_axis_4_8_throughput = ['1', '2']
    plt.plot(x_axis_4_8_throughput, throughput_4_8, 'ro-', label='line1')
    plt.legend(["4-48 Hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Throughput (Bytes/second)')
    plt.title("Throughput vs Number of Malicious Nodes 4 - 8 Hops TCP")
    plt.grid()
    plt.show()


def static_4_8_tcp_throughput_bar():
    throughput_4_8 = [25228.61028, 18994.88055]
    x_axis_4_8_throughput = ['1', '2']
    plt.bar(x_axis_4_8_throughput, throughput_4_8, width=0.4, color='orange')
    plt.legend(["4-8 Hops"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (Bytes/second)')
    plt.title("Throughput vs Number of Malicious Nodes For 4-8 Hops \n In TCP Syn Flood Attack")
    plt.show()


def static_throughput_13_48_hops_bar():
    throughput_1_3 = [74311.42046, 0, 76144.19244, 146269.8973]
    throughput_4_8 = [25228.61028, 18994.88055, 0, 0]
    x_axis_1_1348_throughput = ['1', '2', '3', '4']
    X_axis = np.arange(len(x_axis_1_1348_throughput))
    plt.bar(X_axis - 0.2, throughput_1_3, 0.4)
    plt.bar(X_axis + 0.2, throughput_4_8, 0.4)

    plt.xticks(X_axis, x_axis_1_1348_throughput)
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Number of Malicious Nodes For 1-3 & 4-8 Hops \n In TCP & UDP Flood Attack")
    plt.show()


def static_throughput_13_48_hops_line():
    throughput_1_3 = [74311.42046, 76144.19244, 146269.8973]
    throughput_4_8 = [25228.61028, 18994.88055, data_none]

    x_axis_1_1348_throughput = ['1', '2', '3']
    line1 = plt.plot(x_axis_1_1348_throughput, throughput_1_3, 'bo-', label='line1')
    line2 = plt.plot(x_axis_1_1348_throughput, throughput_4_8, 'ro-', label='line2')
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Throughput (Bytes/second)')
    plt.title("Throughput vs Number of Malicious Nodes 1 - 3 and 4 - 8 Hops")
    plt.grid()
    plt.show()


def static_pdr_1_3_hops_line():
    pdr_1_3 = [76.9384, 69.4444, 60.4651]
    x_axis_1_3_pdr = ['1', '3', '4']
    plt.plot(x_axis_1_3_pdr, pdr_1_3, 'ro-', label='line1')
    plt.legend(["1 - 3 Hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('PDR (Bytes/second)')
    plt.title("Packet Delivery Ratio vs Number of Malicious Nodes 1 - 3 Hops TCP")
    plt.grid()
    plt.show()


def static_pdr_1_3_hops_bar():
    pdr_1_3 = [76.9384, 69.4444, 60.4651]
    x_axis_1_3_pdr = ['1', '3', '4']
    plt.bar(x_axis_1_3_pdr, pdr_1_3, width=0.4)
    plt.legend(["1-3 Hops"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Packet Delivery Ratio (%)')
    plt.title("Packet Delivery Ratio (PDR) vs Number of Malicious Nodes For 4-8 Hops \n In TCP Syn Flood attack")
    plt.show()


def static_pdr_4_8_hops_line():
    pdr_4_8 = [79.9878, 21.2121]
    x_axis_4_8_pdr = ['1', '2']
    plt.plot(x_axis_4_8_pdr, pdr_4_8, 'ro-', label='line1')
    plt.legend(["4 - 8 Hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('PDR (Bytes/second)')
    plt.title("Packet Delivery Ratio vs Number of Malicious Nodes 4 - 8 Hops TCP")
    plt.grid()
    plt.show()


def static_pdr_4_8_hops_bar():
    pdr_4_8 = [72.7642, 21.2121]
    x_axis_4_8_pdr = ['1', '2']
    plt.bar(x_axis_4_8_pdr, pdr_4_8, width=0.4, color='orange')
    plt.legend(["4-8 Hops"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Packet Delivery Ratio (%)')
    plt.title("Packet Delivery Ratio (PDR) vs Number of Malicious Nodes For 4-8 Hops \n In TCP Syn Flood attack")
    plt.show()


def static_pdr_13_48_hops_line():
    pdr_1_3 = [76.9384, 69.4444, 60.4651]
    pdr_4_8 = [79.9878, 21.2121, data_none]

    x_axis_1_1348_throughput = ['1', '2', '3']
    line1 = plt.plot(x_axis_1_1348_throughput, pdr_1_3, 'bo-', label='line1')
    line2 = plt.plot(x_axis_1_1348_throughput, pdr_4_8, 'ro-', label='line2')
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper right")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('PDR (Bytes/second))')
    plt.title("Packet Delivery Ratio vs Number of Malicious Nodes 1 - 3 and 4 - 8 Hops")
    plt.grid()
    plt.show()


def static_pdr_malicious_duration_13hops_line():
    pdr30 = [76.9384, 72.4444, 60.4651]
    pdr60 = [68.9054, 59.6547, 54.6785]
    pdr90 = [66.7694, 53.4876, 49.3487]
    pdr120 = [50.5763, 46.5632, 35.6539]

    x_axis_1_1348_throughput = ['1', '3', '4']
    line1 = plt.plot(x_axis_1_1348_throughput, pdr30, 'bo-', label='line1')
    line2 = plt.plot(x_axis_1_1348_throughput, pdr60, 'ro-', label='line2')
    line1 = plt.plot(x_axis_1_1348_throughput, pdr90, 'go-', label='line3')
    line2 = plt.plot(x_axis_1_1348_throughput, pdr120, 'co-', label='line4')
    plt.legend(["Duration: 30", "Duration: 60", "Duration: 90", "Duration: 120"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Packet Delivery Ratio (%))')
    plt.title("Packet Delivery Ratio (PDR) vs Number of Malicious Nodes & Duration Of Attack For 1-3 Hops")
    plt.grid()
    plt.show()


def static_pdr_13_48_hops_bar():
    pdr_1_3 = [76.9384, 0, 69.4444, 60.4651]
    pdr_4_8 = [79.9878, 21.2121, 0, 0]
    x_axis_1_1348_pdr = ['1', '2', '3', '4']
    X_axis = np.arange(len(x_axis_1_1348_pdr))
    plt.bar(X_axis - 0.2, pdr_1_3, 0.4)
    plt.bar(X_axis + 0.2, pdr_4_8, 0.4)

    plt.xticks(X_axis, x_axis_1_1348_pdr)
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Packet Delivery Ratio (%)')
    plt.title("Packet Delivery Ratio vs Number Of Malicious Nodes For 1-3 and 4-8 Hops \n In TCP & UDP Flood Attack")
    plt.show()


def static_packetloss_13_48_hops_bar():
    pdr_1_3 = [23.06, 0, 30.56, 39.53]
    pdr_4_8 = [20.01, 77.03, 0, 0]
    x_axis_1_1348_pdr = ['1', '2', '3', '4']
    X_axis = np.arange(len(x_axis_1_1348_pdr))
    plt.bar(X_axis - 0.2, pdr_1_3, 0.4)
    plt.bar(X_axis + 0.2, pdr_4_8, 0.4)

    plt.xticks(X_axis, x_axis_1_1348_pdr)
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Packet Loss (%)')
    plt.title("Packet Loss vs Number Of Malicious Nodes For 1-3 and 4-8 Hops \n In TCP & UDP Flood Attack")
    plt.show()


def static_ThroughputvsAttackDuration_1_3_line():
    throughput1_3hops = [29606.24161, 9135.572, 8092.818, 7341.432]
    duration1_3hops = [30, 60, 90, 120]
    throughput4_8hops = [35727.74467, 17146.467, 11072.764, 9381.766]
    plt.plot(duration1_3hops, throughput1_3hops, 'bo-', label='line1')
    plt.plot(duration1_3hops, throughput4_8hops, 'ro-', label='line1')
    plt.legend(["1-3 Hops", "4-8 Hops"], loc="upper right")
    plt.xlabel('Duration (in seconds)')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Attack Duration In 1-3 Hops & 4-8 Hops")
    plt.grid()
    plt.show()


def static_ThroughputvsAttackDurationForAll_line():
    throughput1node = [29606.24161, 9135.572, 8092.818, 7341.432]
    throughput2nodes = [47887.60919, 36754.54321, 27896.47658, 1598.86547]
    throughput3nodes = [76144.19244, 16226.292, 16237.61, 16133.888]
    throughput4nodes = [146269.8973, 21615.439, 21120.256, 20867]
    duration1_3hops = [30, 60, 90, 120]
    throughput4_8hops = [35727.74467, 17146.467, 11072.764, 9381.766]
    plt.plot(duration1_3hops, throughput1node, 'bo-', label='line1')
    plt.plot(duration1_3hops, throughput2nodes, 'ro-', label='line1')
    plt.plot(duration1_3hops, throughput3nodes, 'co-', label='line1')
    plt.plot(duration1_3hops, throughput4nodes, 'go-', label='line1')
    plt.grid()
    plt.legend(["1 Malicious Node", "2 Malicious Nodes", "3 Malicious Nodes", "4 Malicious Nodes"], loc="upper right")
    plt.xlabel('Duration (in seconds)')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Attack Duration & Number Of Malicious Nodes")
    plt.show()


def mobility_2_throughput_tcp_convoy_line():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [12907.597, 17977.170, 24266.882, 25294.338]
    plt.plot(x_axis_throughput, throughput, 'bo-', label='line1')
    plt.legend(["convoy"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput 2 Minutes Convoy")
    plt.grid()
    plt.show()

# This function plots the diagram of throughput for the TCP SYN flood attack
# in the mobile network where the nodes move for two minutes
# bar style diagram
def mobility_2_throughput_tcp_convoy_bar():
    x_axis_throughput = ['1', '2', '3', '4'] # The number of malicious nodes 1,2,3 &4
    throughput = [12907.597, 17977.170, 24266.882, 25294.338] # The calculated throughput
    plt.bar(x_axis_throughput, throughput, width=0.4, color='green')
    plt.legend(["Convoy Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput For 2 Minutes Convoy Network")
    plt.show()


def mobility_10_throughput_tcp_convoy_line():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [12367.390, 11387.278, 14734.138, 26044.667]
    plt.plot(x_axis_throughput, throughput, 'bo-', label='line1')
    plt.legend(["Convoy Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput 10 Minutes Convoy")
    plt.grid()
    plt.show()


def mobility_10_throughput_tcp_convoy_bar():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [12367.390, 11387.278, 14734.138, 26044.667]
    plt.bar(x_axis_throughput, throughput, width=0.4, color="green")
    plt.legend(["Convoy Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput For 10 Minutes Convoy Network")
    plt.show()


def mobility_2_throughput_tcp_random_line():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [15711.881, 20236.438, 15401.798, 26780.126]
    plt.plot(x_axis_throughput, throughput, 'bo-', label='line1')
    plt.legend(["Random"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput 2 Minutes Random")
    plt.grid()
    plt.show()


def mobility_2_throughput_tcp_random_bar():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [15711.881, 20236.438, 15401.798, 26780.126]
    plt.bar(x_axis_throughput, throughput, width=0.4, color='magenta')
    plt.legend(["Random Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput For 2 Minutes Random Network")
    plt.show()


def mobility_10_throughput_tcp_random_line():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [11855.627, 11412.859, 21546.439, 17525.643]
    plt.plot(x_axis_throughput, throughput, 'bo-', label='line1')
    plt.legend(["convoy"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput 10 Minutes Random")
    plt.grid()
    plt.show()


def mobility_10_throughput_tcp_random_bar():
    x_axis_throughput = ['1', '2', '3', '4']
    throughput = [11855.627, 11412.859, 21546.439, 17525.643]
    plt.bar(x_axis_throughput, throughput, width=0.4, color='magenta')
    plt.legend(["Convoy Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput For 10 Minutes Random Network")
    plt.show()


def mobility_2_delay_tcp_convoy_line():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.342, 0.460, 0.380, 0.422]
    plt.plot(x_axis_delay, delay, 'bo-', label='line1')
    plt.legend(["Convoy"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay in 2 Minutes Convoy")
    plt.grid()
    plt.show()


def mobility_2_delay_tcp_convoy_bar():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.342, 0.460, 0.380, 0.422]
    plt.bar(x_axis_delay, delay, width=0.4, color='green')
    plt.legend(["Convoy Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay In 2 Minutes Convoy Network")
    plt.show()


def mobility_2_delay_tcp_random_line():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.367, 0.424, 1.174, 0.483]
    plt.plot(x_axis_delay, delay, 'bo-', label='line1')
    plt.legend(["Random Mode"], loc="upper left", color='green')
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay in 2 Minutes Random Network")
    plt.grid()
    plt.show()


def mobility_2_delay_tcp_random_bar():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.367, 0.424, 1.174, 0.483]
    plt.bar(x_axis_delay, delay, width=0.4, color='green')
    plt.legend(["Random Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay In 2 Minutes Random Network")
    # plt.grid()
    plt.show()


def mobility_10_delay_tcp_random_line():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.334, 0.232, 0.425, 0.781]
    plt.plot(x_axis_delay, delay, 'bo-', label='line1')
    plt.legend(["Random"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay in 10 Minutes Random")
    plt.grid()
    plt.show()


def mobility_10_delay_tcp_random_bar():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.334, 0.232, 0.425, 0.781]
    plt.bar(x_axis_delay, delay, width=0.4, color='magenta')
    plt.legend(["Random Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay In 10 Minutes Random Network")
    plt.show()


def mobility_10_delay_tcp_convoy_line():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.313, 0.232, 0.315, 0.781]
    plt.plot(x_axis_delay, delay, 'bo-', label='line1')
    plt.legend(["Convoy"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay In 10 Minutes Convoy")
    plt.grid()
    plt.show()


def mobility_10_delay_tcp_convoy_bar():
    x_axis_delay = ['1', '2', '3', '4']
    delay = [0.313, 0.232, 0.315, 0.781]
    plt.bar(x_axis_delay, delay, width=0.4, color='magenta')
    plt.legend(["Convoy Mode"], loc="upper left")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Delay (in seconds)')
    plt.title("Delay In 10 Minutes Convoy Network")
    plt.show()


def mobility_2_pdr_convoy_line():
    x_axis_pdr = ['1', '2', '3', '4']
    pdr = [14.634, 7.090, 7.692, 13.423]
    plt.plot(x_axis_pdr, pdr, 'bo-', label='line1')
    plt.legend(["Convoy"], loc="upper left")
    plt.xlabel('#Number Malicious Nodes')
    plt.ylabel('PDR (%)')
    plt.title("PDR  in 2 Minutes Convoy")
    plt.grid()
    plt.show()


def mobility_2_pdr_convoy_bar():
    x_axis_pdr = ['1', '2', '3', '4']
    pdr = [14.634, 7.090, 7.692, 13.423]
    plt.bar(x_axis_pdr, pdr, width=0.4, color='green')
    plt.legend(["Convoy"], loc="upper right")
    plt.xlabel('Number Of Malicious Nodes')
    plt.ylabel('Packet Delivery Ratio (%)')
    plt.title("Packet Delivery Ratio (PDR) In 2 Minutes Convoy Network")
    plt.show()


def mobility_2_throughput_duration_convoy_line():
    x_axis_pdr = [30, 60, 90, 120]
    throughput = [29606.24161, 9135.572, 8092.818, 7341.432]
    z = np.polyfit(x_axis_pdr, throughput, 2)
    p = np.poly1d(z)
    plt.plot(x_axis_pdr, throughput, 'bo-', label='line1')
    plt.plot(x_axis_pdr, p(x_axis_pdr), 'ro-', label='line1')
    plt.legend(["Convoy", "Trend line"], loc="upper right")
    plt.xlabel('Duration in seconds')
    plt.ylabel('Throughput (Bytes/second)')
    plt.title("Throughput vs Attack Duration for one malicious node")
    plt.grid()
    plt.show()


def mobility_2_throughput_duration_random_line():
    x_axis_pdr = [30, 60, 90, 120]
    throughput = [29606.24161, 9135.572, 8092.818, 7341.432]
    z = np.polyfit(x_axis_pdr, throughput, 2)
    p = np.poly1d(z)
    plt.plot(x_axis_pdr, throughput, 'bo-', label='line1')
    plt.plot(x_axis_pdr, p(x_axis_pdr), 'bo-', label='line2')
    plt.legend(["Convoy", "Trend line"], loc="upper right")
    plt.xlabel('Duration in seconds')
    plt.ylabel('Throughput (Bytes/second)')
    plt.title("Throughput vs Attack Duration for one malicious node")
    plt.grid()
    plt.show()


def mobility_2_throughput_duration_convoy_line():
    # TCP Flood Attack
    x_axis_pdr = [30, 60, 90, 120]
    throughput_convoy1 = [11961.919, 12907.597, 12339.607, 11870.437]
    throughput_convoy2 = [15610.884, 18439.831, 16887.894, 12999.170]
    throughput_convoy3 = [19968.479, 19472.359, 17941.396, 15266.882]
    throughput_convoy4 = [26294.338, 25266.682, 18968.479, 17439.861]

    plt.plot(x_axis_pdr, throughput_convoy1, 'bo-', label='line1')
    plt.plot(x_axis_pdr, throughput_convoy2, 'ro-', label='line2')
    plt.plot(x_axis_pdr, throughput_convoy3, 'mo-', label='line2')
    plt.plot(x_axis_pdr, throughput_convoy4, 'co-', label='line2')

    plt.legend(["1 Malicious Node", "2 Malicious Nodes", "3 Malicious Nodes", "4 Malicious Nodes"], loc="upper right")
    plt.xlabel('Duration Of Attack (in seconds)')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Attack Duration & Number Of Malicious Nodes \n In 2 Minutes Convoy Mode Network")
    plt.grid()
    plt.show()


def mobility_2_throughput_duration_random_line():
    # TCP Flood Attack
    x_axis_pdr = [30, 60, 90, 120]
    throughput_convoy1 = [15711.881, 13011.127, 12941.277, 11809.178]
    throughput_convoy2 = [18706.363, 16470.619, 14724.792, 13236.438]
    throughput_convoy3 = [24968.479, 18472.359, 16759.542, 15901.798]
    throughput_convoy4 = [32294.338, 30266.682, 25968.479, 23780.126]

    plt.plot(x_axis_pdr, throughput_convoy1, 'bo-', label='line1')
    plt.plot(x_axis_pdr, throughput_convoy2, 'ro-', label='line2')
    plt.plot(x_axis_pdr, throughput_convoy3, 'mo-', label='line3')
    plt.plot(x_axis_pdr, throughput_convoy4, 'co-', label='line4')

    plt.legend(["1 Malicious Node", "2 Malicious Nodes", "3 Malicious Nodes", "4 Malicious Nodes"], loc="upper right")
    plt.xlabel('Duration Of Attack (in seconds)')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Attack Duration & Number Of Malicious Nodes \n In 2 Minutes Random Mode Network")
    plt.grid()
    plt.show()


def mobility_10_throughput_duration_random_line():
    # TCP Flood Attack
    x_axis_pdr = [100, 200, 300, 600]
    throughput_convoy1 = [11855.627, 15711.881, 13011.127, 13203.310]
    throughput_convoy2 = [18706.363, 17470.619, 15653.352, 12387.278]
    throughput_convoy3 = [26044.667, 23968.479, 21472.359, 20892.451]
    throughput_convoy4 = [24294.338, 21266.682, 18968.479, 16990.002]

    plt.plot(x_axis_pdr, throughput_convoy1, 'bo-', label='line1')
    plt.plot(x_axis_pdr, throughput_convoy2, 'ro-', label='line2')
    plt.plot(x_axis_pdr, throughput_convoy3, 'mo-', label='line3')
    plt.plot(x_axis_pdr, throughput_convoy4, 'co-', label='line4')

    plt.legend(["1 Malicious Node", "2 Malicious Nodes", "3 Malicious Nodes", "4 Malicious Nodes"], loc="upper right")
    plt.xlabel('Duration Of Attack (in seconds)')
    plt.ylabel('Throughput (bytes/second)')
    plt.title("Throughput vs Attack Duration & Number Of Malicious Nodes \n In 10 Minutes Random Mode Network")
    plt.grid()
    plt.show()


# Call the functions below to plot the diagrams
# Some functions are uncommented thus the diagrams are created automatically when you run the program
static_delay_1_3_hops_line()
static_delay_1_3_hops_bar()
static_delay_4_8_hops_line()
static_delay_4_8_hops_bar()
static_delay_13_48_hops_bar()

# ** Uncomment the comments below to plot all the diagrams produced from the software **

# static_delay_13_48_hops_line()
# static_delay_4_8_hops_TCP_UDP_bar()
# static_1_3_tcp_throughput_line()
# static_1_3_tcp_throughput_bar()
# static_4_8_tcp_throughput_line()
# static_4_8_tcp_throughput_bar()
# static_throughput_13_48_hops_bar()
# static_throughput_13_48_hops_line()
# static_pdr_1_3_hops_line()
# static_pdr_1_3_hops_bar()
# static_pdr_4_8_hops_line()
# static_pdr_4_8_hops_bar()
# static_pdr_13_48_hops_line()
# static_pdr_13_48_hops_bar()
# mobility_2_throughput_tcp_convoy_line()
# mobility_2_throughput_tcp_convoy_bar()
# mobility_10_throughput_tcp_convoy_line()
# mobility_10_throughput_tcp_convoy_bar()
# mobility_2_throughput_tcp_random_line()
# mobility_2_throughput_tcp_random_bar()
# mobility_10_throughput_tcp_random_bar()
# mobility_10_throughput_tcp_random_line()
# mobility_2_delay_tcp_convoy_line()
# mobility_2_delay_tcp_convoy_bar()
# mobility_2_delay_tcp_random_line()
# mobility_2_delay_tcp_random_bar()
# mobility_10_delay_tcp_convoy_line()
# mobility_10_delay_tcp_convoy_bar()
# mobility_10_delay_tcp_random_line()
# mobility_10_delay_tcp_random_bar()
# mobility_2_pdr_convoy_line()
# mobility_2_pdr_convoy_bar()
# static_ThroughputvsAttackDuration_1_3_line()
# static_ThroughputvsAttackDurationForAll_line()
# static_packetloss_13_48_hops_bar()
# mobility_2_throughput_duration_convoy_line()
# mobility_2_throughput_duration_random_line()
# mobility_10_throughput_duration_random_line()
# static_pdr_malicious_duration_13hops_line()
