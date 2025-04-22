import os, argparse
import re, math
import statistics
import numpy as np

cal = {}
data_lists = {}
times = {}

def cal_statistics(default_entry):
    global data_lists

    sum_ = {}
    avg = {}
    p50 = {}
    p90 = {}
    p99 = {}
    stdev = {}
    max_ = {}

    for bench_name, data_list in data_lists.items():
        if not data_list:
            sum_[bench_name] = default_entry
            avg[bench_name] = default_entry
            p50[bench_name] = default_entry
            p90[bench_name] = default_entry
            p99[bench_name] = default_entry
            stdev[bench_name] = default_entry
            max_[bench_name] = default_entry
            continue

        # Calculate sums, averages, and max values, excluding STW_count
        sums = {}
        averages = {}
        max_values = {}
        for key in data_list[0].keys():
            if key != "STW_count":  # Exclude STW_count from calculations
                values = [entry[key] for entry in data_list]
                sums[key] = sum(values)
                averages[key] = sums[key] / len(data_list)  # Average calculation
                max_values[key] = max(values)  # Max calculation
        
        sum_[bench_name] = sums
        avg[bench_name] = averages
        max_[bench_name] = max_values

        # Calculate standard deviation, excluding STW_count, using precomputed averages
        stdev_values = {}
        for key in data_list[0].keys():
            if key != "STW_count":  # Exclude STW_count from calculations
                mean = averages[key]
                stdev_values[key] = math.sqrt(sum((entry[key] - mean) ** 2 for entry in data_list) / len(data_list))

        stdev[bench_name] = stdev_values

        # Calculate percentiles, excluding STW_count
        p50_values = {}
        p90_values = {}
        p99_values = {}
        
        for key in data_list[0].keys():
            if key != "STW_count":  # Exclude STW_count from calculations
                values = [entry[key] for entry in data_list]
                
                # Calculate percentiles
                p50_values[key] = np.percentile(values, 50)  # 50th percentile
                p90_values[key] = np.percentile(values, 90)  # 90th percentile
                p99_values[key] = np.percentile(values, 99)  # 99th percentile

        p50[bench_name] = p50_values
        p90[bench_name] = p90_values
        p99[bench_name] = p99_values

    return sum_, avg, p50, p90, p99, stdev, max_

def hushvac_parse(f, bench_name) :
    global data_lists

    try :
        data_list = data_lists[bench_name]
    except :
        data_list = []
    
    data = f.read()
    pattern = re.compile(
        r"STW_count: (\d+)\s+STW_time: (\d+) ms\s+"
        r"1st_mark_time: (\d+) ms\s+2nd_mark_time: (\d+) ms\s+sweep_time: (\d+) ms\s+"
        r"1st_mark_tick: (\d+) ms\s+2nd_mark_tick: (\d+) ms\s+sweep_tick: (\d+) ms"
    )

    # Parse the data and store each block in a list of dictionaries
    for match in pattern.finditer(data):
        entry = {
            "STW_count": int(match.group(1)),
            "STW_time": int(match.group(2)),
            "1st_mark_time": int(match.group(3)),
            "2nd_mark_time": int(match.group(4)),
            "sweep_time": int(match.group(5)),
            "1st_mark_clk": int(match.group(6)),
            "2nd_mark_clk": int(match.group(7)),
            "sweep_clk": int(match.group(8))
        }
        data_list.append(entry)

    data_lists[bench_name] = data_list

def markus_parse(f, bench_name) :
    global data_lists

    try :
        data_list = data_lists[bench_name]
    except :
        data_list = []
    
    data = f.read()

    # Regular expression to match each STW_count block
    pattern = re.compile(
        r"STW count:\s+(\d+)\n"
        r"\s+mark_time:\s*([\d,]*)\n"
        r"\s+mark_time_clk:\s*([\d,]*)\n"
        r"\s+sweep_time:\s*([\d,]*)\n"
        r"\s+sweep_time_clk:\s*([\d,]*)\n"
        r"\s+sweep_time2:\s*([\d,]*)\n"
        r"\s+sweep_time2_clk:\s*([\d,]*)\n"
    )

    # Parse the data and store each block in a list of dictionaries
    for match in pattern.finditer(data):
        entry = {
            "STW_count": int(match.group(1)),
            "mark_time": int(match.group(2)),
            "mark_time_clk": int(match.group(3)),
            "sweep_time": int(match.group(4)),
            "sweep_time_clk": int(match.group(5)),
            "sweep_time2": int(match.group(6)),
            "sweep_time2_clk": int(match.group(7))
        }
        data_list.append(entry)

    # print(bench_name, data_list)

    data_lists[bench_name] = data_list


def minesweeper_parse(f, bench_name) :
    global data_lists

    try :
        data_list = data_lists[bench_name]
    except :
        data_list = []
    
    data = f.read()

    # Regular expression to match each STW_count block
    pattern = re.compile(
        r"STW count:\s+(\d+)\n"
        r"\s+Total STW_time:\s*([\d,]*)\n"
        r"\s+1st_mark_time:\s*([\d,]*)\n"
        r"\s+1st_mark_clk:\s*([\d,]*)\n"
        r"\s+2nd_mark_time:\s*([\d,]*)\n"
        r"\s+2nd_mark_clk:\s*([\d,]*)\n"
        r"\s+sweep_time:\s*([\d,]*)\n"
        r"\s+sweep_clk:\s*([\d,]*)\n"
    )


    # Parse the data and store each block in a list of dictionaries
    for match in pattern.finditer(data):
        entry = {
            "STW_count": int(match.group(1)),
            "Total_STW_time": int(match.group(2).replace(",", "") or 0),  # Remove commas
            "1st_mark_time": int(match.group(3).replace(",", "") or 0),   # Remove commas
            "1st_mark_clk": int(match.group(4).replace(",", "") or 0),   # Remove commas
            "2nd_mark_time": int(match.group(5).replace(",", "") or 0),   # Remove commas
            "2nd_mark_clk": int(match.group(6).replace(",", "") or 0),   # Remove commas
            "sweep_time": int(match.group(7).replace(",", "") or 0),       # Remove commas
            "sweep_clk": int(match.group(8).replace(",", "") or 0)     # Remove commas
        }
        data_list.append(entry)

    # print(bench_name, data_list)

    data_lists[bench_name] = data_list

def parse_total(f, bench_name) :
    global times

    try :
        time_list = times[bench_name]
    except :
        time_list = []
    
    data = f.read()

    pattern = re.compile(r'User time \(seconds\): (\d+\.\d+)\s+System time \(seconds\): (\d+\.\d+)')

    for match in pattern.finditer(data) :
        entry = {
            "User time": float(match.group(1)),
            "System time": float(match.group(2))
        }

        time_list.append(entry)
    
    times[bench_name] = time_list    


if __name__ == "__main__" :
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", type=str, help="Directory to search for time.out files")

    args = parser.parse_args()

    path = os.getcwd() + "/" + args.directory

    for filename in os.listdir(path) :
        if "time.out" in filename :
            bench_name = ".".join(filename.split(".")[:2])
            with open(path + "/" + filename, "r") as f :
                if "hushvac" in args.directory :
                    hushvac_parse(f, bench_name)
                elif "markus" in args.directory :
                    markus_parse(f, bench_name)
                elif "minesweeper" in args.directory :
                    minesweeper_parse(f, bench_name)
                else :
                    print("Unknown benchmark name")
                    exit(1)
                
                f.seek(0)
                parse_total(f, bench_name)

    total_times = {}
    for bench_name, time_list in times.items() :
        total_time = 0
        for time in time_list :
            total_time += time["User time"] + time["System time"]
        total_times[bench_name] = total_time

    if "hushvac" in args.directory or "minesweeper" in args.directory :
        print("Benchmark, 1st_mark_real, 1st_mark_clk, 1st_mark_stdev, 2nd_mark_real, 2nd_mark_clk, 2nd_mark_stdev, sweep_real, sweep_clk, sweep_stdev, avg, stdev, p50, p90, p99, max, total_clk")
        for bench_name, _ in sorted(data_lists.items()) :
            sum_, avg, p50, p90, p99, stdev, max_ = cal_statistics({'STW_time': 0, '1st_mark_time': 0, '2nd_mark_time': 0, 'sweep_time': 0, '1st_mark_clk': 0, '2nd_mark_clk': 0, 'sweep_clk': 0})
            print("%s, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f"
            %(bench_name, 
                sum_[bench_name]["1st_mark_time"] / 1000,
                sum_[bench_name]["1st_mark_clk"] / 1000, 
                stdev[bench_name]["1st_mark_clk"] / 1000, 
                sum_[bench_name]["2nd_mark_time"] / 1000, 
                sum_[bench_name]["2nd_mark_clk"] / 1000, 
                stdev[bench_name]["2nd_mark_clk"] / 1000, 
                sum_[bench_name]["sweep_time"] / 1000, 
                sum_[bench_name]["sweep_clk"] / 1000, 
                stdev[bench_name]["sweep_clk"] / 1000,
                avg[bench_name]["2nd_mark_clk"] / 1000, 
                stdev[bench_name]["2nd_mark_clk"] / 1000, 
                p50[bench_name]["2nd_mark_clk"] / 1000, 
                p90[bench_name]["2nd_mark_clk"] / 1000, 
                p99[bench_name]["2nd_mark_clk"] / 1000, 
                max_[bench_name]["2nd_mark_clk"] / 1000,
                total_times[bench_name]))
        
    elif "markus" in args.directory :
        print("Benchmark, mark_real, mark_clk, mark_stdev, sweep_real, sweep_clk, sweep_stdev, avg, stdev, p50, p90, p99, max, total_clk")
        for bench_name, _ in sorted(data_lists.items()) :
            sum_, avg, p50, p90, p99, stdev, max_ = cal_statistics({'STW_time': 0, 'mark_time': 0, 'sweep_time': 0, 'mark_time_clk': 0, 'sweep_time_clk': 0})
            print("%s, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f, %.3f"
            %(bench_name, 
                sum_[bench_name]["mark_time"] / 1000, 
                sum_[bench_name]["mark_time_clk"] / 1000, 
                stdev[bench_name]["mark_time_clk"] / 1000, 
                sum_[bench_name]["sweep_time"] / 1000, 
                sum_[bench_name]["sweep_time_clk"] / 1000, 
                stdev[bench_name]["sweep_time_clk"] / 1000, 
                avg[bench_name]["mark_time_clk"] / 1000, 
                stdev[bench_name]["mark_time_clk"] / 1000, 
                p50[bench_name]["mark_time_clk"] / 1000, 
                p90[bench_name]["mark_time_clk"] / 1000, 
                p99[bench_name]["mark_time_clk"] / 1000, 
                max_[bench_name]["mark_time_clk"] / 1000,
                total_times[bench_name]))