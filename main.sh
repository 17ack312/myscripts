out='index.html'

f1='web_name.txt'
f2='web_url.txt'
clear

read -p "enter your name : " name
echo -e '
<!DOCTYPE html>
<html>
<head>
        <title>WELCOME 
</title>
</head>

<style>
table{
margin: 60px;
}
th,tr,td{
        border: 2px solid black;
        padding: 10px
}
#head{
        font-family: algerian;
        text-decoration: underline;
}
</style>

<script>
function startTime() {
  const today = new Date();
  let h = today.getHours();
  let m = today.getMinutes();
  let s = today.getSeconds();
  m = checkTime(m);
  s = checkTime(s);
  document.getElementById("time").innerHTML =  h + ":" + m + ":" + s;
  setTimeout(startTime, 1000);
}

function checkTime(i) {
  if (i < 10) {i = "0" + i};  // add zero in front of numbers < 10
  return i;
}

function dt(){
        const d = new Date();
        var m=d.getMonth() + 1;
        var y=d.getFullYear();
        var d1=d.getDate();
       document.getElementById("date").innerHTML = d1+"/"+m+"/"+y;



}

</script>


<body onload="startTime(),dt()">
        <center><h1 id="head">Welcome ' > intro.txt
echo $name >> intro.txt
echo '</h1></center>
        <div id="datetime" align="center">current date : <span id="date"></span></div>
        <div id="datetime" align="center">current time : <span id="time"></span></div>

<div align="center"><table>
        <th>
                <td><u>Name</u></td>
                <td><u>Link</u></td>
        </th>
' >> intro.txt

echo '
</table></div>
</body>
</html>
' > outro.txt


if [ ! -f web_name.txt ]
then
touch web_name.txt
fi
if [ ! -f web_url.txt ]
then
touch web_url.txt
fi


get_details(){
q1='y'

while [ "$q1" = y -o "$q1" = Y ]
do
read -r -p "enter website name : " web

if [ ${#web} -eq 0 ]
then
	echo -e "website name is too short"
exit
fi
	flag=`cat web_name.txt | grep -qix "$web";echo $?`
 	if [ $flag -eq 1 ]
 	then
		read -r -p "enter url : " url
		if [ ${#url} -eq 0 ]
		then
	 		echo -e "website is too short"
			exit
		fi
		flag=`cat web_url.txt | grep -qix "$url";echo $?`
		if [ $flag -eq 1 ]
		then
	 		echo $url >> web_url.txt
			echo $web >> web_name.txt
		else
			echo -e "$url already exist"
		fi

	else
		echo -e "$web already exist"
	fi

	read -p "want to enter again ?(Y/n)" q1
	if [ "$q1" = n -o "$q1" = N ]
	then
		break
	else
	q1='y'
	fi


done
}

run(){
len=`cat $f1 | wc -l`
count=1

cat intro.txt > $out
while [ $count -le $len ]
do
	echo -e '<tr><td>' >> $out
	echo -e $count >> $out
	echo -e '</td><td>' >> $out
	sed -n $count" p" $f1 >> $out
	echo -e '</td><td><a target="_blank" href="' >> $out
	sed -n $count" p" $f2 >> $out
	echo -e '"><button>GO</button></a></td><tr>' >> $out
	((count++))
done
cat outro.txt >> $out

}


read -p "Modify Databse ?(y/N) : " q
if [ ${#q} -gt 0 ]
then
	echo -e " [1] Insert Data"
	echo -e " [2] Reset DataBase"
	read c
	if [ $c -eq 2 ]
	then
		rm -f $f1 $f2
	fi
	if [ $c -eq 1 ]
	then
		clear
		echo -e "Avaiable Data"
		paste -d'\t' $f1 $f2 | cat -n
		get_details
	fi

fi

lenA=`cat $f1 | wc -l`
lenB=`cat $f2 | wc -l`

if [ $lenA -eq $lenB ]
then
#	echo running well
	run
else
	rm $f1 $f2
fi

