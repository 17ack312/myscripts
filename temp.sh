clear

echo -e 'enter name : \c'
read name
name=${name^^}
#echo $name

#ip=`ifconfig | grep -w inet | tr -s '\t' ' ' | cut -d' ' -f3 | head -1`

#link='http://'$ip'/'$name'/'
link='https://vgwebserv/sgwebdiary/Dashboard/to_web/'"$name"'/'
f1=$name/web_name.txt
f2=$name/web_url.txt
#echo $f1 $f2


if [  ! -d $name ]
then
	mkdir $name
	chmod 777 $name
	if [ ! -f $f1 -a ! -f $f2 ]
	then
		touch $f1 $f2
	fi
else
chmod 777 $name/*
fi

out=$name/index.html
#echo $out



get_details(){
q1='y'

while [ "$q1" = y -o "$q1" = Y ]
do
read -r -p "enter website name : " web

if [ ${#web} -eq 0 ]
then
        echo -e "website name is too short"
	echo -e $link
exit
fi
        flag=`cat $f1 | grep -qix "$web";echo $?`
        if [ $flag -eq 1 ]
        then
                read -r -p "enter url : " url
                if [ ${#url} -eq 0 ]
                then
                        echo -e "website is too short"
			echo -e $link
                        exit
                fi
                flag=`cat $f2 | grep -qix "$url";echo $?`
                if [ $flag -eq 1 ]
                then
                        echo $url >> $f2
                        echo $web >> $f1
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

echo -e '<!DOCTYPE html>
<html>
<head>
<title>WELCOME</title>
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
</head>' > $out

echo -e '<body onload="startTime(),dt()">' >> $out
echo -e '<center><h1 id="head">Welcome '"$name"'</h1></center>' >> $out

echo -e '<div id="datetime" align="center">current date : <span id="date"></span></div>
        <div id="datetime" align="center">current time : <span id="time"></span></div>

        <div align="center"><table>
        <th>
                <td><u>Name</u></td>
                <td><u>Link</u></td>
        </th>' >> $out

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


echo -e '</table></div>
</body>
</html>' >> $out


}




q2='N'
read -p "Modify Databse ?(y/N) : " q2
if [ ${#q2} -gt 0 ]
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
                echo -e "Available Data"
                paste -d'\t' $f1 $f2 | cat -n
                get_details
        fi

fi

lenA=`cat $f1 | wc -l`
lenB=`cat $f2 | wc -l`

if [ $lenA -eq $lenB ]
then
#       echo running well
        run
else
        rm $f1 $f2
fi




#get_details
#run

#sudo cp -rf $name /var/www/html/
#sudo service apache2 start
echo $link
