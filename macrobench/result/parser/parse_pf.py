import os, argparse

cal = {}

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
                    t = [0, 0] # major fault, minor fault
                for line in f :
                    if line.startswith("\tMajor (requiring I/O)") :
                        t[0] += int(line.split(": ")[1].rstrip("\n"))
                    elif line.startswith("\tMinor (reclaiming a frame)") :
                        t[1] += int(line.split(": ")[1].rstrip("\n"))
                
                cal[bench_name] = t

    for name, val in sorted(cal.items()) :
        print("%s, %d, %d"%(name, val[0], val[1]))