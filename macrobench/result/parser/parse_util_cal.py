import os, argparse

cal = {}

def timestamp_to_time(timestamp) :
    time = timestamp.split(":")
    result, count = 0, 0
    for t in reversed(time) :
        result += float(t) * (60 ** count)
        count += 1

    return result

if __name__ == "__main__" :
    parser = argparse.ArgumentParser()
    parser.add_argument("-d", "--directory", type=str, help="Directory to search for time.out files")

    args = parser.parse_args()

    path = os.getcwd() + "/" + args.directory
    for filename in os.listdir(path) :
        if "time.out" in filename :
            bench_name = ".".join(filename.split(".")[:2])
            with open(path + "/" + filename, "r") as f :
                try :
                    t = cal[bench_name]
                except :
                    t = [0, 0, 0] # user_time, sys_time, real_time
                for line in f :
                    if line.startswith("\tUser time") :
                        t[0] += float(line.split(": ")[1].rstrip("\n"))
                    elif line.startswith("\tSystem time") :
                        t[1] += float(line.split(": ")[1].rstrip("\n"))
                    elif line.startswith("\tElapsed (wall clock) time") :
                        t[2] += timestamp_to_time(line.split(": ")[1].rstrip("\n"))
                
                cal[bench_name] = t

    for name, val in sorted(cal.items()) :
        print("%s, %.2f"%(name, (val[0] + val[1]) / val[2] * 100))