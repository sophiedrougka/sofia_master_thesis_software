# ....DROUGKA SOFIA ....#
# ....Program to Analyze Network Behavior through CSV exported pcap Files.... #
# ....Developed in the context the Master thesis....#
# ....In Athens University of Economics and Business....#

import pandas as pd
from matplotlib import pyplot as plt, axes
from statistics import mean
import ast

# The path to the .pcap files
filepath = "STATIC_MULTI_1_3_6TO7.CSV"
destination_ip = '10.0.0.7'

plot_title = filepath[:-4]
df = pd.read_csv(filepath)

# List with all protocol names found in the .pcap file
list_of_protocols = []
# Dictionary of packets' frequency per protocol
dict_of_protocols = {}
# Dictionary of packets' length per protocol
dict_of_lengths = {}
# Dictionary of minimum and maximum packets' length per protocol
dict_of_min_max = {}
# List of source IP addresses found in the .pcap file
list_of_source_ips = []
# Dictionary of source IP addresses frequency
dict_of_source_ips = {}
dict_of_protocols_length = {}
# Dictionary of "info" field per packet
dict_of_protocol_info = {}
# dictionary of packets average length per protocol
protcl_average_length = {}
# Count how many TCP appears in .pcap file
count_tcp = 0
# Position of elements in list
index = 0


# function to get protools that appear in the pcap file
def protocols():
    for protocol_name in df["Protocol"]:
        if protocol_name not in list_of_protocols:
            list_of_protocols.append(protocol_name)
    return list_of_protocols


# Get a list of source IP addresses
def list_of_ips():
    for ip in df["Source"]:
        if ip not in list_of_source_ips:
            list_of_source_ips.append(ip)
    return list_of_source_ips


# Initialize dictionary for protocols to create an initial dictionary with protocols
def initialize_dict_of_protocols(dict_of_protocols1):
    keys1 = protocols()
    dict_of_protocols1 = dict_of_protocols1.fromkeys(keys1)
    for protocol_key in dict_of_protocols1:
        dict_of_protocols1[protocol_key] = 0
    return dict_of_protocols1


# Initialize dictionary for IP addresses to create an initial dictionary with IPs
def initialize_dict_of_ips(dict_of_source_ips1):
    keys1 = list_of_ips()
    dict_of_source_ips1 = dict_of_source_ips1.fromkeys(keys1)
    for ip_key in dict_of_source_ips1:
        dict_of_source_ips1[ip_key] = 0
    return dict_of_source_ips1


# Update protocols' dictionary with the total number of each protocol's appearance in the .pcap file
def update_dict_of_protocols(initial_dict):
    for protocol1 in df["Protocol"]:
        initial_dict[protocol1] += 1
    return initial_dict


# Update dictionary of source IPs with the total number of each source IPs appearance in the .pcap file
def update_dict_of_ips(dict_of_source_ips1):
    for key in df["Source"]:
        dict_of_source_ips1[key] += 1
    return dict_of_source_ips1


# Initialize dictionary of the minimum and maximum packet length of each protocol
def init_dict_of_protocols_length(dict_of_protocols_length1):
    protocols_list = protocols()
    dict_of_protocols_length1 = dict_of_protocols_length1.fromkeys(protocols_list)
    for key in protocols_list:
        lengths2, minmax2 = min_max_length_of_protocol(key)
        dict_of_protocols_length1[key] = lengths2
    return dict_of_protocols_length1


# Initialize dictionary of each protocol's information
def init_dict_of_protocol_info(dictinfo):
    infolist1 = []
    keys = protocols()
    dictinfo = dictinfo.fromkeys(keys)
    for key in keys:
        count = 0
        for item in df["Protocol"]:
            if item == key:
                infolist1.append(df["Info"][count])
            count += 1

        dictinfo[key] = infolist1
        infolist1 = []
    return dictinfo


# Get the protocol's minimum and maximum length of the .pcap file
def min_max_length_of_protocol(protocol2):
    index1 = 0
    length_list = []  # auxiliary length list
    minmaxlist = []  # final list with minimum and maximum packet length of each protocol

    for item in df["Protocol"]:
        if item == protocol2:
            length1 = df["Length"][index1]
            length_list.append(length1)

        index1 += 1
    min_len = min(length_list)
    minmaxlist.append(min_len)
    max_len = max(length_list)
    minmaxlist.append(max_len)
    return length_list, minmaxlist


# Get the protocol with the minimum and the protocol with the maximum value
def min_max_length_of_protocols(protocol_list):
    for item2 in protocol_list:
        lengths2, minmax2 = min_max_length_of_protocol(item2)
        dict_of_lengths[item2] = minmax2
    return dict_of_lengths


# Get the source IPs which have the minimum and the maximum frequency in the .pcap file
def get_min_max_ips(protocol):
    position = 0
    ip_list1 = []
    ip_list2 = []
    dict1 = {}  # IP with minimum frequency appearance
    dict2 = {}  # IP with maximum frequency appearance

    length_list, minmaxlist = min_max_length_of_protocol(protocol)

    for item in df["Protocol"]:
        if item == protocol:
            length = df["Length"][position]
            ip_source = df["Source"][position]
            if length == minmaxlist[0]:
                if ip_source not in ip_list1:
                    ip_list1.append(ip_source)
            if length == minmaxlist[1]:
                if ip_source not in ip_list2:
                    ip_list2.append(ip_source)

        position += 1
    label1 = protocol + ":" + str(minmaxlist[0])
    label2 = protocol + ":" + str(minmaxlist[1])
    dict1[label1] = ip_list1
    dict2[label2] = ip_list2

    return dict1, dict2


# list of protocols
myprotocols = protocols()
print(myprotocols)
dict_of_protocols = initialize_dict_of_protocols(dict_of_protocols)

dict_of_protocols = update_dict_of_protocols(dict_of_protocols)
print(dict_of_protocols)
dict_of_min_max = min_max_length_of_protocols(myprotocols)
print(dict_of_min_max)
iplist1, iplist2 = get_min_max_ips("TCP")


# plot frequency value per protocol type
# i.e. how many times a TCP protocol appears in the .pcap file
def plot_of_protocols(protocols_list):
    plot_list1 = []
    for key11 in dict_of_protocols:
        plot_list1.append(dict_of_protocols[key11])

    plt.bar(protocols_list, plot_list1)
    plt.title("FILENAME: " + plot_title + "\n FREQUENCY DISTRIBUTION OF PROTOCOLS")
    plt.ylabel("FREQUENCY OF PROTOCOLS")
    plt.xlabel("PROTOCOLS")
    plt.show()


# plot frequency of each source IP
def plot_of_ips():
    ip_keys = dict_of_source_ips.keys()
    ip_values = dict_of_source_ips.values()
    plt.bar(ip_keys, ip_values)
    plt.title("FILENAME: " + plot_title + "\n FREQUENCY DISTRIBUTION OF SOURCE IP ADDRESSES")
    plt.ylabel("FREQUENCY OF SOURCE IP ADDRESSES")
    plt.xlabel("IP ADDRESS")
    plt.xticks(rotation=80)
    plt.tight_layout()
    plt.show()


# return the minimum and maximum length of the given protocol
def protocol_length_range(myprotocol):
    length_range, lst22 = min_max_length_of_protocol(myprotocol)
    return length_range


# plot the length distribution per protocol
def plot_protocol_length_range(myprotocol=None):
    y_value = protocol_length_range(myprotocol)
    x_value = [i for i in range(1, len(y_value) + 1)]
    plt.bar(x_value, y_value)
    plt.title("FILENAME: " + plot_title + "\n PROTOCOL LENGTH RANGE")
    plt.xlabel(myprotocol.upper() + " " + "PROTOCOL")
    plt.ylabel(myprotocol.upper() + " " + "PROTOCOL LENGTH RANGE")
    plt.show()


# Get the average length of each protocol
def protocols_average_length(avg_length_dict):
    protocols20 = protocols()
    avg_length_dict = avg_length_dict.fromkeys(protocols20)
    listlengths = init_dict_of_protocols_length(dict_of_protocols_length)
    for protcl in protocols20:
        if protcl in listlengths.keys():
            average_length = mean(listlengths[protcl])
            avg_length_dict[protcl] = average_length
    return avg_length_dict


# Plot of average length per protocol
def plot_protocol_average_length():
    y_values = []
    x_values = []
    file_dict = {}
    file_dict.fromkeys(filepath)
    for x in protcl_average_length:
        y_values.append(protcl_average_length[x])
        x_values.append(x)

    plt.bar(x_values, y_values)
    plt.xlabel("PROTOCOL")
    plt.ylabel("PROTOCOL AVERAGE LENGTH")
    plt.title("FILENAME: " + plot_title + "\n PROTOCOLS AVERAGE LENGTH")
    plt.show()
    file_dict[plot_title] = y_values
    print("TEST FILE DICT ", file_dict)

    with open("results.txt", 'a') as f:
        f.write(str(file_dict) + "\n")


# Get the stored dictionary from file
def get_dict_from_file(file_path):
    new_dict = {}
    count = 0
    with open(file_path) as f:
        lines = f.readlines()
        for line in lines:
            if len(line) != 0:
                d = ast.literal_eval(line)
                new_dict[count] = d
            count += 1
            print("IMPORT DICTIONARY FROM FILE", d)
    return new_dict


# save in file the dictionary with protocol's frequency
def save_protocols_frequency():
    file_dict = {}
    file_dict.fromkeys(plot_title)
    file_dict[plot_title] = dict_of_protocols
    with open("protocols_frequency.txt", 'a') as f:
        f.write(str(file_dict) + "\n")


# save in file the dictionary with protocol's packet's length
def save_avg_protocol_length():
    file_length_dict = {}
    file_length_dict.fromkeys(plot_title)
    file_length_dict[plot_title] = protcl_average_length
    with open("packets_length.txt", 'a') as f:
        f.write(str(file_length_dict) + "\n")


# print protocols with ips in minimum, maximum length
for protocol in myprotocols:
    dict1, dict2 = get_min_max_ips(protocol)
    print(dict1)
    print(dict2)

iplist = list_of_ips()
print("IP LIST", "\n", iplist)

dict_of_source_ips = initialize_dict_of_ips(dict_of_source_ips)
print(dict_of_source_ips)
dict_of_source_ips = update_dict_of_ips(dict_of_source_ips)
print(dict_of_source_ips)

# print max min ip attempts
print("IP WITH MAX ATTEMPTS..")

v = list(dict_of_source_ips.values())  # v is the list of dictionary values
k = list(dict_of_source_ips.keys())  # k is the list of dictionary keys
print(k[v.index(max(v))])
print(max(v))

# plot of source ips
plot_of_ips()

# print min max list
minmaxlistkeys = list(dict_of_min_max.keys())
minmaxlistvalues = list(dict_of_min_max.values())
maxlengths = []

for list in minmaxlistvalues:
    maxvalue = list[1]
    maxlengths.append(maxvalue)


# plot of protocols
def plot_of_protocols_length_range():
    for pp in list_of_protocols:
        print("PLOT " + pp)
        plot_protocol_length_range(pp)


# Get all data concerning a specific protocol from the saved file
def get_protocol_data_from_file(file_path):
    new_dict = {}
    count = 0
    with open(file_path) as f:
        lines = f.readlines()
        for line in lines:
            if len(line) != 0:
                d = ast.literal_eval(line)
                new_dict[count] = d
            count += 1
    return new_dict


# Read the protocol's frequencies which are saved as dictionary in file
def get_protocol_frequency_from_file(saved_dict, protocol_name):
    freq_lst = []
    for file_key in saved_dict:

        dictionary_in_file = saved_dict[file_key]
        for key1 in dictionary_in_file:
            dict6 = dictionary_in_file[key1]
            print(dict6)
            for key2 in dict6:
                if key2 == protocol_name:
                    freq_lst.append(dict6[key2])
    mean_freq = mean(freq_lst)
    return freq_lst, mean_freq


# Return the protocol's average length from the saved file
def get_protocol_avg_length_from_file(saved_dict, protocol_name):
    length_lst1 = []
    for key55 in saved_dict:
        dict_in_file = saved_dict[key55]
        for key1 in dict_in_file:
            dict6 = dict_in_file[key1]
            print(dict6)
            for key2 in dict6:
                if key2 == protocol_name:
                    length_lst1.append(dict6[key2])
    return length_lst1, mean(length_lst1)


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


# Call the functions to plot the graphs
plot_of_protocols_length_range()
plot_protocol_average_length()

newdict = get_protocol_data_from_file("protocols_frequency.txt")
print("COMBINED DICTIONARY ", newdict)

list_of_protocols_frequency = []
dict_of_protocols_frequency = {}
list_of_protocols_length = []
dict_of_protocols_length = {}
dctfreq, mn = get_protocol_frequency_from_file(newdict, "TAPA")
print(dctfreq)
print(mn)

# plot frequencies from file

for prot_key in list_of_protocols:
    dctfreq, mn = get_protocol_frequency_from_file(newdict, prot_key)
    list_of_protocols_frequency.append(mn)
    dict_of_protocols_frequency[prot_key] = mn
print("FRQUENCIES", list_of_protocols_frequency)
print("DICTIONARY", dict_of_protocols_frequency)

list_of_protocols_in_file = []
x_value = []
y_value = []

# plot protocol's average frequency
for prot_key1 in dict_of_protocols_frequency:
    x_value.append(prot_key1)
    y_value.append(dict_of_protocols_frequency[prot_key1])
plt.bar(x_value, y_value)
plt.xlabel("PROTOCOL")
plt.ylabel("PROTOCOL AVERAGE FREQUENCY")
plt.title("PROTOCOLS AVERAGE FRQUENCY FROM EXPERIMENTS")
plt.show()

avg_len_dict = get_protocol_data_from_file("packets_length.txt")
print("AVERAGE LENGTH OF PROTOCOLS", avg_len_dict)
length_lst, mean_length = get_protocol_avg_length_from_file(avg_len_dict, "TAPA")
print("LIST OF AVG LENGTHS", length_lst, mean_length)

# plot frequencies from file
for prot_key in list_of_protocols:
    dctfreq, mn = get_protocol_avg_length_from_file(avg_len_dict, prot_key)
    list_of_protocols_length.append(mn)
    dict_of_protocols_length[prot_key] = mn
print("AVG LENGTHS", list_of_protocols_length)
print("DICTIONARY", dict_of_protocols_length)

x_value = []
y_value = []

# plot avg lengths from file
for prot_key1 in dict_of_protocols_length:
    x_value.append(prot_key1)
    y_value.append(dict_of_protocols_length[prot_key1])
plt.bar(x_value, y_value)
plt.xlabel("PROTOCOL")
plt.ylabel("PROTOCOL AVERAGE LENGTH")
plt.title("PROTOCOLS AVERAGE LENGTH FROM EXPERIMENTS")
plt.show()

save_protocols_frequency()
save_avg_protocol_length()
dict_packets_length = get_dict_from_file("packets_length.txt")
print(dict_packets_length)

print("PLOT AVERAGE LENGTH OF TCP ")
plot_protocol_length_range("TCP")

general_plot_function(frequency_of_connection_to_destination_ip(destination_ip), "ATTACK IPS", "FREQUENCY", "FREQUENCY OF ATTACK IPS")
