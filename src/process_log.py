# your Python code to implement the features could be placed here
# note that you may use any language, there is no preference towards Python
import signal
import sys
import os
import mmap
from collections import Counter
import heapq
from datetime import datetime
import time
from collections import OrderedDict
import re


def exit_gracefully(signum, frame):
    # restore the original signal handler as otherwise evil things will happen
    # in raw_input when CTRL+C is pressed, and our signal handler is not re-entrant
    signal.signal(signal.SIGINT, original_sigint)

    try:
        if raw_input("\nConfirm to quit? (y/n)> ").lower().startswith('y'):
            sys.exit(1)

    except KeyboardInterrupt:
        print("force to quit")
        sys.exit(1)

    # restore the exit gracefully handler here
    signal.signal(signal.SIGINT, exit_gracefully)


def read_file(file_path):
    print "reading file", file_path
    if os.path.exists(file_path):
        try:
            f = open(file_path, 'r')
            mm = mmap.mmap(f.fileno(), 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
        except IOError:
            print "Could not read file:", file_path
            sys.exit()
    else:
        print "Could not find the file:", file_path
        sys.exit()
    return f, mm


def write_file(file_path):
    print "opening file", file_path
    try:
        f = open(file_path, 'w')
    except IOError:
        print "Could not open file:", file_path
        sys.exit()
    return f


def feature1(input_file, output_file):
    """
    Implementation of feature1. Count for number of IP occurrance and output highest 10
    :param input_file:
    :param output_file: file name that we write to
    :return: void
    """
    ip_add = []
    f, mm = read_file(input_file)

    for line in iter(mm.readline, ""):
        temp = line.split(" ", 1)
        ip = temp[0]
        if len(ip) < 1:
            continue
        else:
            ip_add.append(ip)
    mm.close()
    f.close()

    sorted_dic = Counter(ip_add)
    f = write_file(output_file)
    for key, value in sorted_dic.most_common(10):
        result = "%s,%s\n" % (key, value)
        f.write(result)
    f.close()


def feature2(input_file, output_file):
    byte_record = {}
    f, mm = read_file(input_file)

    for line in iter(mm.readline, ""):
        temp = line.split(" ", 1)
        ip = temp[0]
        if len(ip) < 1:
            continue
        else:
            resource = temp[1][5:].split()[3]
            value = temp[1][5:].split()[6]
            if resource in byte_record:
                byte_record[resource] += float(value)
            else:
                byte_record[resource] = float(value)
    mm.close()
    f.close()

    heap = [(value, key) for key, value in byte_record.items()]
    largest = heapq.nlargest(10, heap)

    f = write_file(output_file)
    for key, value in largest:
        result = "%s\n" % value
        f.write(result)
    f.close()


def feature3(input_file, output_file):
    f, mm = read_file(input_file)

    time_times = []
    for line in iter(mm.readline, ""):
        temp = line.split(" ", 1)
        ip = temp[0]
        if len(ip) < 1:
            continue
        else:
            record = temp[1][5:].split()
            time_stamp = record[0]
            if len(time_times) < 1 or time_times[-1][0] != time_stamp:
                time_times.append((time_stamp, 1))
            else:
                new_times = time_times[-1][1] + 1
                time_times[-1] = (time_stamp, new_times)

    mm.close()
    f.close()

    sec_list = []
    for item in time_times:
        d = datetime.strptime(item[0], '%d/%b/%Y:%H:%M:%S')
        time_in_sec = time.mktime(d.timetuple())
        sec_list.append((time_in_sec, item[1]))

    # build heap by sliding window of time period

    start_time = sec_list[0][0]
    end_time = sec_list[-1][0]
    res_heap = []
    slide_window = []
    end = 0
    window_times = 0

    while start_time <= end_time:
        d_time = datetime.fromtimestamp(start_time).strftime('%d/%b/%Y:%H:%M:%S')

        if len(slide_window) != 0:
            if slide_window[0][0] < start_time:
                window_times -= slide_window[0][1]
                slide_window.pop(0)

        while end < len(sec_list):
            if sec_list[end][0] <= start_time + 60:
                slide_window.append(sec_list[end])
                window_times += sec_list[end][1]
                end += 1

        res_heap.append((-window_times, d_time))
        start_time += 1

    # res_heap[12] = (12, res_heap[12][1])

    # sort_time = sorted(res_heap, key=lambda x: (x[0], datetime.strptime(x[1], '%d/%b/%Y:%H:%M:%S')), reverse=True)
    # res_heap = sorted(res_heap, key=lambda x: (datetime.strptime(x[1], '%d/%b/%Y:%H:%M:%S')))
    heapq.heapify(res_heap)
    num = 10
    sort_time = []
    while num > 0:
        temp = []
        if len(res_heap) != 0:
            temp.append(heapq.heappop(res_heap))
            while len(res_heap) != 0 and res_heap[0][0] == temp[0][0]:
                temp.append(heapq.heappop(res_heap))
            temp = sorted(temp, key=lambda x: (datetime.strptime(x[1], '%d/%b/%Y:%H:%M:%S')))
            for item in temp:
                if num > 0:
                    sort_time.append(item)
                    num -= 1
                else:
                    break
        else:
            break

    f = write_file(output_file)
    for key, value in sort_time:
        result = "%s -0400,%s\n" % (value, -key)
        f.write(result)
    f.close()


def feature4(input_file, output_file):
    # found 304, record in dictionary with IP as key, and rest of things as value
    time_record = {}
    result_record = {}
    f, mm = read_file(input_file)

    for line in iter(mm.readline, ""):
        temp = line.split(" ", 1)
        ip = temp[0]
        if len(ip) < 1:
            continue
        else:
            record = temp[1].split()
            print record
            if record[7] == '304':
                date = datetime.strptime(record[2][1:], '%d/%b/%Y:%H:%M:%S')
                time_in_sec = time.mktime(date.timetuple())
                if ip in time_record:
                    print record[2][1:]
                    print time_in_sec
                    if time_in_sec - time_record[ip][0] < 20:
                        time_record[ip][1] += 1
                        if time_record[ip] >= 3:
                            result_record[ip] = record
                    else:
                        time_record.pop(ip)
                else:
                    time_record[ip] = [time_in_sec, 1]
            elif record[7] == '200':
                if ip in time_record:
                    time_record.pop(ip)

    mm.close()
    f.close()

    print result_record

    f = write_file(output_file)
    for key, value in result_record:
        time_record = "%s %s %s %s %s %s %s %s %s %s\n" \
                      % (key, value[0], value[1], value[2], value[3],
                         value[4], value[5], value[6], value[7], value[8])
        print time_record
        f.write(time_record)
    f.close()


def main():
    argv = sys.argv
    feature1(argv[1], argv[2])
    feature2(argv[1], argv[4])
    feature3(argv[1], argv[3])
    feature4(argv[1], argv[5])


if __name__ == '__main__':
    # store the original SIGINT handler
    original_sigint = signal.getsignal(signal.SIGINT)
    signal.signal(signal.SIGINT, exit_gracefully)
    main()
