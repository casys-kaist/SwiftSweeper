# iterate all directories and run $ sudo clean_all.sh

for dir in */ ; do
  if [ -f "${dir}test_output.txt"  ]; then
    # Run build_all.py script
    (cd "$dir" && rm -rf test_output.txt)
  else
    echo "No test_output.txt found in ${dir}"
  fi
done

# if results directory exists, then clean up!!
if [ -d "results" ]; then 
  rm -rf results
  echo "Removed results directory";
fi