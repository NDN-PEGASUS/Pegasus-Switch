# Run stop_pcl_switchd.sh
echo "Running stop_pcl_switchd.sh..."
./stop_pcl_switchd.sh
if [ $? -ne 0 ]; then
    echo "stop_pcl_switchd.sh failed. Exiting."
    exit 1
fi

# Run build.sh
echo "Running build.sh..."
./build.sh
if [ $? -ne 0 ]; then
    echo "build.sh failed. Exiting."
    exit 1
fi

# Run start_pcl_switchd.sh
echo "Running start_pcl_switchd.sh..."
./start_pcl_switchd.sh
if [ $? -ne 0 ]; then
    echo "start_pcl_switchd.sh failed. Exiting."
    exit 1
fi

# Run run_pcl_bfshell.sh
echo "Running run_pcl_bfshell.sh..."
./run_pcl_bfshell.sh
if [ $? -ne 0 ]; then
    echo "run_pcl_bfshell.sh failed. Exiting."
    exit 1
fi