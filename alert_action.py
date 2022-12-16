# ....DROUGKA SOFIA ....#
# ....Software to Measure Statistics and Attack Patterns from .PCAP Files.... #
# ....Developed in the context the Master thesis of System Development and Cybersecurity....#
# ....Athens University of Economics and Business....#

import csv
import pandas as pd
from matplotlib import pyplot as plt, axes
from statistics import mean
import numpy as np

header = ["Protocol", "Frequency", "Minimum_Length", "Average_Length", "Maximum_Length", "Duration", "ATTACK_TYPE"]
# A sample .Pcap file
filepath = "STATIC_MULTI_1_3_6TO7.CSV"
destination_ip = '10.0.0.7'
plot_title = filepath[:-4]
# Import data from .csv file and convert it to dataframe
df = pd.read_csv(filepath)

# The following are some lists and dictionaries which are responsible for saving the data
list_of_protocols = []
dict_of_protocols = {}
dict_of_lengths = {}
dict_of_min_max = {}
list_of_source_ips = []
dict_of_source_ips = {}
dict_of_protocols_length = {}
dict_of_protocol_info = {}
protcl_average_length = {}
dict_of_ip_protocol = {}
dict_of_ip_length = {}
count_tcp = 0
index = 0
start_time = 0
end_time = 0
dict_start_end_of_time = {}


# This function gets the total list of all protocols
def protocols():
    for protocol1 in df["Protocol"]:
        if protocol1 not in list_of_protocols:
            list_of_protocols.append(protocol1)
    return list_of_protocols


# This function gets a total list containing all source IP addresses
def list_of_ips():
    for ip in df["Source"]:
        if ip not in list_of_source_ips:
            list_of_source_ips.append(ip)
    return list_of_source_ips


# Initialize the dictionary of number of occurrences per protocol
def initialize_dict_of_protocols(dict_of_protocols1):
    keys1 = protocols()

    dict_of_protocols1 = dict_of_protocols1.fromkeys(keys1)
    for key1 in dict_of_protocols1:
        dict_of_protocols1[key1] = 0
    return dict_of_protocols1


def initialize_dict_of_ips(dict_of_source_ips1):
    keys1 = list_of_ips()

    dict_of_source_ips1 = dict_of_source_ips1.fromkeys(keys1)
    for key1 in dict_of_source_ips1:
        dict_of_source_ips1[key1] = 0
    return dict_of_source_ips1


# Dictionary of length, IPs and protocols
def list_of_IP_protocol_length():
    position = 0
    sourceIP = list_of_ips()
    ip_protocol_list = []
    ip_protocol_length = []
    for key in sourceIP:
        for key1 in df["Source"]:
            if key == key1:
                ip_protocol_list.append(df["Protocol"][position])
                ip_protocol_length.append(df["Length"][position])
            position += 1
        dict_of_ip_protocol[key] = ip_protocol_list
        dict_of_ip_length[key] = ip_protocol_length
        ip_protocol_list = []
        ip_protocol_length = []
        position = 0

    with open("list_of_IPs_with_protocols.txt", 'a') as f:
        f.write(str(dict_of_ip_protocol) + "\n")
    with open("list_of_IPs_with_length.txt", 'a') as f:
        f.write(str(dict_of_ip_length) + "\n")
    return dict_of_ip_protocol, dict_of_ip_length


def frequency_of_protocols(dict11):
    dict11 = initialize_dict_of_protocols(dict11)

    for key in df["Protocol"]:
        dict11[key] += 1
    return dict11


def update_dict_of_ips(dict_of_source_ips1):
    for key in df["Source"]:
        dict_of_source_ips1[key] += 1

    return dict_of_source_ips1


def get_max_ip_freq(dict_of_source_ips1):
    dict_ips = {}
    dict_of_source_ips1 = update_dict_of_ips(initialize_dict_of_ips(dict_of_source_ips1))
    keys = list(dict_of_source_ips1.keys())
    values = list(dict_of_source_ips1.values())
    spc_ip = keys[values.index(max(values))]
    num_attacks = max(values)
    for key in dict_of_source_ips1:
        if key != spc_ip:
            dict_ips[key] = dict_of_source_ips1[key]

    return spc_ip, num_attacks, dict_ips


# minimum, maximum length of protocol
def min_max_avg_length_of_protocol(protocol2):
    index1 = 0
    length_list = []
    minmaxlist = []
    # index_list = []

    for item in df["Protocol"]:
        if item == protocol2:
            length1 = df["Length"][index1]
            length_list.append(length1)
            # index_list.append(index1)

        index1 += 1
    min_len = min(length_list)
    minmaxlist.append(min_len)
    max_len = max(length_list)
    minmaxlist.append(max_len)
    avg_len = mean(length_list)
    minmaxlist.append(avg_len)
    return length_list, minmaxlist


def min_max_avg_length_of_protocols(list2):
    for item2 in list2:
        lengths2, minmax2 = min_max_avg_length_of_protocol(item2)
        dict_of_lengths[item2] = minmax2
    return dict_of_lengths


def get_max_protocol_length(protocol):
    dict_of_min_max_avg_1 = min_max_avg_length_of_protocols(protocols())
    for key in dict_of_min_max_avg_1:
        if key == protocol:
            max_len = dict_of_min_max_avg_1[key][1]
    return max_len


def get_avg_protocol_length(protocol):
    dict_of_min_max_avg_1 = min_max_avg_length_of_protocols(protocols())
    for key in dict_of_min_max_avg_1:
        if key == protocol:
            avg_len = dict_of_min_max_avg_1[key][2]
    return avg_len


def frequency_of_connection_to_destination_ip(dest_ip1):
    count = 0;
    dict_of_attack_ips = {}
    # INITIALIZE IP ADDRESSES
    for ip_add in df["Source"]:
        if df["Destination"][count] == dest_ip1:
            dict_of_attack_ips[ip_add] = 0
        count += 1
    count = 0
    for ip_add in df["Source"]:
        if df["Destination"][count] == dest_ip1:
            dict_of_attack_ips[ip_add] += 1
        count += 1
    return dict_of_attack_ips


def alert_on_packet_avg_length():
    protocol = input("Please enter protocol name:\n")
    min_range = input("Please enter minimum range:\n")
    max_range = input("Please enter maximum range:\n")
    avg_len = get_avg_protocol_length(protocol)
    if avg_len in range(int(min_range), int(max_range)):
        print("POSSIBLE ATTACK")
    else:
        print("NORMAL CONDITION")


def plot_of_ips(dict_of_source_ips1):
    dict_of_source_ips1 = update_dict_of_ips(initialize_dict_of_ips(dict_of_source_ips1))
    ip_keys = dict_of_source_ips1.keys()
    ip_values = dict_of_source_ips1.values()
    plt.bar(ip_keys, ip_values)
    plt.title("FILENAME: " + plot_title + "\n FREQUENCY DISTRIBUTION OF SOURCE IP ADDRESSES")
    plt.ylabel("FREQUENCY OF SOURCE IP ADDRESSES")
    plt.xlabel("IP ADDRESS")
    plt.xticks(rotation=80)
    plt.tight_layout()
    plt.show()


# plot procedure
def plot_of_protocols_frequency():
    protocols_list = protocols()
    dict_of_protocols1 = frequency_of_protocols(initialize_dict_of_protocols(dict_of_protocols))
    plot_list1 = []
    for key11 in dict_of_protocols1:
        plot_list1.append(dict_of_protocols1[key11])

    plt.bar(protocols_list, plot_list1)
    plt.title("FILENAME: " + plot_title + "\n FREQUENCY DISTRIBUTION OF PROTOCOLS ")
    plt.ylabel("FREQUENCY OF PROTOCOLS")
    plt.xlabel("PROTOCOLS")
    plt.show()


def plot_of_protocols_length():
    x_val = []
    y_val = []
    y_val1 = []
    protocols_list = protocols()

    for key in protocols_list:
        x_val.append(key)

    for key in protocols_list:
        y_val.append(get_max_protocol_length(key))

    for key in protocols_list:
        y_val1.append(get_avg_protocol_length(key))

    X_axis = np.arange(len(x_val))

    plt.bar(X_axis - 0.2, y_val, 0.4)
    plt.bar(X_axis + 0.2, y_val1, 0.4)
    plt.title("FILENAME: " + plot_title + "\n MAX, AVG DISTRIBUTION OF PROTOCOLS ")
    plt.ylabel("LENGTH OF PROTOCOLS")
    plt.xlabel("PROTOCOLS")
    plt.show()


def general_plot_function(mydictionary, xlabel, ylabel, title):
    x_val = []
    y_val = []
    for key in mydictionary:
        x_val.append(key)
        y_val.append(mydictionary[key])
    plt.bar(x_val, y_val)
    plt.title("FILENAME: " + plot_title + "\n " + title)
    plt.xlabel(xlabel)
    plt.ylabel(ylabel)
    plt.show()


# This function collects all the produced statistical data in a dataframe
def packets_analysis(protocols_dictionary, frequencies, attack_type):
    info_list1 = []
    for key in protocols_dictionary:
        # Initialize the list mylist
        mylist = []
        mylist.append(key)
        mylist.append(frequencies[key])
        min_length = protocols_dictionary[key][0]
        mylist.append(min_length)
        avg_length = protocols_dictionary[key][2]
        mylist.append(avg_length)
        max_length = protocols_dictionary[key][1]
        mylist.append(max_length)
        info_list1.append(mylist)
        lst, duration1 = get_time_duration(key)
        mylist.append(duration1)
        mylist.append(attack_type)
    return info_list1


# Calculate time duration per packet/protocol within each corresponding window time
def get_time_duration(myprotocol):
    mylist = []  # saves time duration
    time_window = []  # the time window which contains the start and end time
    count = 0  # index position in dataframe column
    start = 0  # the protocol starts at this time in the time window
    total_duration = 0  # total time duration

    # The start variable indicates the start and the end of the time window
    for item in df["Protocol"]:
        if myprotocol == item and start == 0:
            start_time1 = df["Time"][count]
            # When the variable start becomes 1 this means that the if condition has found the very first time that the
            # the specific protocol given was found!
            start = 1

        # After the very first time when the protocol has been located, if we do not find the protocol in the next line
        # Then the variable start becomes 0 again.
        elif myprotocol != item and start == 1:
            start = 0
            # the end_time variable means the end of the time that the specific protocol has been found.
            end_time1 = df["Time"][count]
            # So, we add in the list named mylist the start and end time of the specific protocol type for the time window
            time_window.append(start_time1)
            time_window.append(end_time1)
            # Add the time window in the main list mylist
            mylist.append(time_window)
            time_window = []
            # The total time duration that the specific protocol was transmitting its packets
            total_duration = total_duration + (end_time1 - start_time1)
        count += 1

    return mylist, total_duration


def load_data(filepath1):
    data_from_csv = pd.read_csv(filepath1)
    return data_from_csv


# One hot encoding for the categorical data of protocol and type of attack
# This function converts the categorical data into binary form to calculate
# them into the neural network
def prepare_data(mydata):
    # Pass data in form of a dataframe mydata
    # Encode the categorical data of Protocol and Attack type which are Strings
    encoded_data = pd.get_dummies(mydata, columns=['Protocol', 'ATTACK_TYPE'])
    return encoded_data


output_file_path = "output_file_12.csv"
with open(output_file_path, 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)

spc_ip, num_attacks, dict_ips = get_max_ip_freq(dict_of_source_ips)
print("SUSPICIOUS IP ADDRESS ", spc_ip)
print("NUMBER OF ATTACKS ", num_attacks)
print("OTHER IP ADDRESSES ", dict_ips)

frc_of_protocol = frequency_of_protocols(dict_of_protocols)
print("FREQUENCIES", frc_of_protocol)

dict_of_min_max_avg = min_max_avg_length_of_protocols(protocols())
print("DICTIONARY OF LENGTHS ", dict_of_min_max_avg)

info_list = packets_analysis(dict_of_min_max_avg, frc_of_protocol, "ddos_tcp_flood’")
print(info_list)

filepath = "info_file_1.csv"
with open(filepath, 'w', encoding='UTF8', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(header)
    writer.writerows(info_list)

data = load_data("info_file_1.csv")
print(data.to_string())
encoded_data = prepare_data(data)
print(encoded_data.to_string())

lst1, duration = get_time_duration("TCP")
# Prints the list with the start and end of the time window that appears the specific protocol
print("The time window for the specific protocol we have chosen. For example, the following list is the time "
      "window for the TCP protocol.")
print(lst1)
print(len(lst1))
print("This the total time duration for the protocol you have chosen: ", duration)
