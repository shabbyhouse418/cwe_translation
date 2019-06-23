index_id_frist=`cat cwe.config |grep "index_id" | awk -F'=' '{ print $2 }' | sed s/[[:space:]]//g`
while true; do
	index_id_sec=`cat cwe.config |grep "index_id" | awk -F'=' '{ print $2 }' | sed s/[[:space:]]//g`
	if [ ${index_id_frist} != ${index_id_sec} ]; then
		echo "\033[40mCWE翻译进度: \033[0m" > /dev/pts/1
    	echo "索引值: $(cat cwe.config |grep "index_id" | awk -F'=' '{ print $2 }' | sed s/[[:space:]]//g)">> /dev/pts/1
    	index_id_frist=`cat cwe.config |grep "index_id" | awk -F'=' '{ print $2 }' | sed s/[[:space:]]//g`
	fi
	sleep 1
done