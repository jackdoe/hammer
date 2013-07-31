make clean all
/sbin/rmmod hammer.ko
/sbin/insmod hammer.ko
killall nc
(echo HTTP/1.1 200 hello kernel | nc -l 12345) &
sleep 1
#echo "129.82.138.26:50001" > /proc/hammer/__control
echo "127.0.0.1:12345@anything_you_say_here_will_apear_in_the_file_upto_80ish_chars" > /proc/hammer/__control
sleep 1
#cat /proc/hammer/c_129*
cat /proc/hammer/c_127*
cat /proc/hammer/s_127*
ls -la /proc/hammer/
echo "hello netcat" > /proc/hammer/c_127*

