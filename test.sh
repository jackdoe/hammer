make clean all
rmmod hammer.ko
insmod hammer.ko
killall nc
(echo hello kernel | nc -l 12345) &
sleep 1
#echo "129.82.138.26:50001" > /proc/hammer/__control
echo "127.0.0.1:12345" > /proc/hammer/__control
sleep 1
#cat /proc/hammer/c_129*
cat /proc/hammer/c_127*
echo "hello netcat" > /proc/hammer/c_127*

