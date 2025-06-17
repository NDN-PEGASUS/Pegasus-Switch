# Run build.sh
echo "Running build.sh..."
./build.sh
if [ $? -ne 0 ]; then
    echo "build.sh failed. Exiting."
    exit 1
fi

# Run install.sh
echo "Running install.sh..."
./install.sh
if [ $? -ne 0 ]; then
    echo "install.sh failed. Exiting."
    exit 1
fi