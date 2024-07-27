#!/bin/bash

function executeCommands()
{
    case $1 in
        0)
            content=$(cat readme)
            echo ${content##* } # Take the last word
            ;;
        1)
            cat ./-
            ;;
        2)
            cat "./spaces in this filename"
            ;;
        3)
            cat inhere/...Hiding-From-You
            ;;
        4)
            # file inhere/*
            cat inhere/-file07
            ;;
        5)
            # find inhere/ -type f -not -executable -size 1033c | xargs file
            content=$(< inhere/maybehere07/.file2) # it automatically deletes all spaces, and if you have 'word1       word2' in the text file, it becomes word1 word2
            echo $content
            ;;
        6)
            # find / -type f -size 33c -user bandit7 -group bandit6
            cat /var/lib/dpkg/info/bandit7.password
            ;;
        7)
            content=$(cat data.txt | grep millionth | cut -f 2)
            echo ${content##* }
            ;;
        8)
            content=$(sort data.txt | uniq -u)
            echo $content
            ;;
        9)
            content=$(strings data.txt | grep -o '==========.*' | cut -d ' ' -f 2 | tail -n 1)
            echo $content
            ;;
        10)
            content=$(cat data.txt | base64 -d | cut -d ' ' -f 4)
            echo $content
            ;;
        11)
            # A-M -> N-Z
            # N-Z -> A-M
            # a-m -> n-z
            # n-z -> a-m
            content=$(cat data.txt | tr 'A-MN-Za-mn-z' 'N-ZA-Mn-za-m' | cut -d ' ' -f 4)
            echo $content
            ;;
        12)
            tempDir=$(mktemp -d)
            cp data.txt $tempDir 
            cd $tempDir
            xxd -r data.txt result.txt
            rm data.txt
            # file result.txt
            mv result.txt result.gz
            gunzip result.gz
            # file result
            mv result result.bz2
            bunzip2 result.bz2
            # file result
            mv result result.gz
            gunzip result.gz
            # file result
            mv result result.tar
            tar -xf result.tar
            rm result.tar
            #file data5.bin
            mv data5.bin data5.bin.tar
            tar -xf data5.bin.tar
            rm data5.bin.tar
            # file data6.bin
            mv data6.bin data6.bin.bz2
            bunzip2 data6.bin.bz2
            # file data6.bin
            mv data6.bin data6.bin.tar
            tar -xf data6.bin.tar
            rm data6.bin.tar
            # file data8.bin
            mv data8.bin data8.bin.gz
            gunzip data8.bin.gz
            # file data8.bin
            content=$(cat data8.bin | cut -d ' ' -f 4)
            echo $content
            ;;
        14)
            currLevelPass=$(cat /etc/bandit_pass/bandit14)
            password=$(cat /etc/bandit_pass/bandit14 | nc localhost 30000 | tail -n 2 | head -n 1)
            echo $password
            ;;
        15)
            # alternative to test: cat /etc/bandit_pass/bandit15 | openssl s_client -connect localhost:30001 -quiet 2>/dev/null | head -n 2 | tail -n 1 
            password=$(cat /etc/bandit_pass/bandit15 | openssl s_client -connect localhost:30001 -ign_eof -quiet | tail -n 2)
            echo $password
            # Server response:
            # Can't use SSL_get_servername
            # depth=0 CN = SnakeOil
            # verify error:num=18:self-signed certificate
            # verify return:1
            # depth=0 CN = SnakeOil
            # verify return:1
            # Correct!
            # password_level
            #
            ;;
        16)
            password=$(cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:31790 -ign_eof -quiet 2>/dev/null | head -n 28 | tail -n 27)
            echo $password
            ;;
        17)
            password=$(diff passwords.old passwords.new | tail -n 1 | cut -d ' ' -f 2)
            echo $password
            ;;
        19)
            # ./bandit20-do
            password=$(./bandit20-do cat /etc/bandit_pass/bandit20)
            echo $password
            ;;
        20)
            currLevelPass=$(cat /etc/bandit_pass/bandit20)
            echo $currLevelPass | nc -l -p 1234 &
            sleep 2
            password=$(./suconnect 1234 | tail -n 0)
            echo $password
            ;;
        21)
            # ls /etc/cron.d
            # cat /etc/cron.d/cronjob_bandit22
            # cat /usr/bin/cronjob_bandit22.sh
            password=$(cat /tmp/t7O6lds9S0RqQh9aMcz6ShpAoZKF7fgv)
            echo $password
            ;;
        22)
            # ls /etc/cron.d
            # cat /etc/cron.d/cronjob_bandit23
            # cat /usr/bin/cronjob_bandit23.sh
            file=$(echo I am user bandit23 | md5sum | cut -d ' ' -f 1)
            password=$(cat /tmp/$file)
            echo $password
            ;;
        23)
            # This level may take a while
            # ls /etc/cron.d
            # cat /etc/cron.d/cronjob_bandit23
            # cat /usr/bin/cronjob_bandit24.sh
            tmpDir=$(mktemp -d)
            chmod 777 $tmpDir
            echo '#!/bin/bash' > /var/spool/bandit24/foo/script.sh
            echo "cat /etc/bandit_pass/bandit24 > $tmpDir/password.txt" >> /var/spool/bandit24/foo/script.sh
            chmod 777 /var/spool/bandit24/foo/script.sh
            touch $tmpDir/password.txt
            chmod 777 $tmpDir/password.txt
            sleep 60
            password=$(cat $tmpDir/password.txt)
            echo $password
            ;;
        24)
            currLevelPass=$(cat /etc/bandit_pass/bandit24)
            tmpDir=$(mktemp -d)
            echo '#!/bin/bash' > $tmpDir/script.sh
            chmod 777 $tmpDir/script.sh
            echo "for i in {0000..9999};" >> $tmpDir/script.sh
            echo "do" >> $tmpDir/script.sh
            echo "echo $currLevelPass \$i" >> $tmpDir/script.sh
            echo "done | nc localhost 30002" >> $tmpDir/script.sh
            password=$($tmpDir/script.sh | tail -n 2 | head -n 1 | cut -d ' ' -f 7)
            echo $password
            ;;
    esac
}

if [[ $# -eq 2 ]]; then
    flag=$1
    case $flag in
        -l|--level)
            level=$2
            if [[ $level =~ ^([0-9]|[1-2][0-9]|3[0-4])$ ]]; then

                # Does bandit_passwords.txt exists? 
                if [[ ! (-e "bandit_passwords.txt") ]]; then
                    echo "Error: bandit_passwords.txt does not exist! Create it, and add 0:bandit0 as first line"
                    exit 1
                fi
                
                # if you want to get the password of a level, you can find it in the previous level
                prevLevel=$(( $level - 1 ))
                prevLevelPassword=$(grep "$prevLevel:" bandit_passwords.txt | cut -d ':' -f 2)
                #echo $prevLevelPassword
                if [[ $prevLevelPassword == "" ]]; then
                    echo "Previous level password does not exist!"
                    exit 1
                fi
                
                password=""
                if [[ $level -eq 14 ]]; then
                    sshpass -p $prevLevelPassword scp -P 2220 bandit13@bandit.labs.overthewire.org:'sshkey.private' ./
                    mv sshkey.private bandit14.sshkey.private
                    chmod g-r bandit14.sshkey.private

                    password=$(ssh bandit14@bandit.labs.overthewire.org -p 2220 -i bandit14.sshkey.private "cat /etc/bandit_pass/bandit14")
                    rm bandit14.sshkey.private
                elif [[ $level -eq 17 ]]; then
                    # nmap -sV -A -p 31000-32000 localhost | grep open
                    privateKey=$(sshpass -p $prevLevelPassword ssh bandit$prevLevel@bandit.labs.overthewire.org -p 2220 "cat /etc/bandit_pass/bandit16 | openssl s_client -connect localhost:31790 -ign_eof -quiet 2>/dev/null | head -n 28 | tail -n 27") # we use 2>/dev/null to silence messages from ssl server
                    echo "$privateKey" > bandit17.sshkey.private # use "$variable" when echo to preserve \n
                    chmod g-rw bandit17.sshkey.private
                    chmod o-r bandit17.sshkey.private

                    password=$(ssh bandit17@bandit.labs.overthewire.org -p 2220 -i bandit17.sshkey.private "cat /etc/bandit_pass/bandit17")
                    rm bandit17.sshkey.private
                elif [[ $level -eq 19 ]]; then
                    # ssh bandit18@bandit.labs.overthewire.org -p 2220 -t /usr/bin/sh avoids .bashrc automatic exit, and it opens a sh shell
                    res=$(sshpass -p $prevLevelPassword ssh bandit18@bandit.labs.overthewire.org -p 2220 -t "cat readme")
                    password="${res%?}" # deletes last character '^M' from the response, why '^M'? No idea... 
                elif [[ $level -eq 26 ]]; then # This solution also writes the password for bandit27
                    # DO NOT MAXIMIZE YOUR TERMINAL WINDOW, OTHERWISE THIS WILL NOT WORK
                    sshpass -p $prevLevelPassword scp -P 2220 bandit25@bandit.labs.overthewire.org:'bandit26.sshkey' ./
                    chmod g-r bandit26.sshkey

                    resize -s 5 100

                    expect expect_bandit26.exp

                    password=$(cat bandit27 | head -n 2 | tail -n 1)
                    password=$(tr -dc '[[:print:]]' <<< "$password")

                    prefix="[?2004l"
                    password=${password#"$prefix"}

                    rm bandit27

                    level="27"

                    # write bandit26 password
                    bandit26=$(cat bandit26 | head -n 2 | tail -n 1)
                    bandit26=$(tr -dc '[[:print:]]' <<< "$bandit26")
                    bandit26=${bandit26#"$prefix"}
                    rm bandit26
                    rm bandit26.sshkey
                    echo "26:$bandit26" >> bandit_passwords.txt
                elif [[ $level -eq 28 ]]; then
                    sshpass -p $prevLevelPassword git clone ssh://bandit27-git@bandit.labs.overthewire.org:2220/home/bandit27-git/repo
                    password=$(cat repo/README | cut -d ' ' -f 8)
                    rm -r -f repo
                elif [[ $level -eq 29 ]]; then
                    sshpass -p $prevLevelPassword git clone ssh://bandit28-git@bandit.labs.overthewire.org:2220/home/bandit28-git/repo
                    cd repo
                    password=$(git show | tail -n 3 | head -n 1 | cut -d ' ' -f 3)
                    cd ..
                    rm -r -f repo
                elif [[ $level -eq 30 ]]; then
                    sshpass -p $prevLevelPassword git clone ssh://bandit29-git@bandit.labs.overthewire.org:2220/home/bandit29-git/repo
                    cd repo
                    git checkout dev
                    password=$(cat README.md | tail -n 2 | head -n 1 | cut -d ' ' -f 3)
                    cd ..
                    rm -r -f repo
                elif [[ $level -eq 31 ]]; then
                    sshpass -p $prevLevelPassword git clone ssh://bandit30-git@bandit.labs.overthewire.org:2220/home/bandit30-git/repo
                    cd repo
                    # git tag
                    password=$(git show secret)
                    cd ..
                    rm -r -f repo
                elif [[ $level -eq 32 ]]; then
                    sshpass -p $prevLevelPassword git clone ssh://bandit31-git@bandit.labs.overthewire.org:2220/home/bandit31-git/repo
                    cd repo
                    rm .gitignore
                    echo "May I come in?" > key.txt
                    git add .
                    git commit -m "Obtaining password"
                    
                    # > foo: Redirects the standard output (stdout) to a file named foo
                    # 2>&1: Redirects the standard error (stderr) to the same location as the stdout. This ensures both stdout and stderr are captured in foo
                    sshpass -p fb5S2xb7bRyFmAvQYQGEqsbhVyJqhnDy git push origin master > ../foo 2>&1
                    cd ..
                    password=$(cat foo | head -n 16 | tail -n 1 | cut -d ' ' -f 2)
                    rm foo
                    rm -r -f repo
                elif [[ $level -eq 33 ]]; then
                    expect expect_bandit33.exp $prevLevelPassword
                    password=$(cat bandit33 | head -n 2 | tail -n 1)
                    rm bandit33
                else
                    password=$(sshpass -p $prevLevelPassword ssh bandit$prevLevel@bandit.labs.overthewire.org -p 2220 "$(declare -f executeCommands); executeCommands $prevLevel")
                fi
                echo "$level:$password" >> bandit_passwords.txt
            else
                echo "Error: bad arguments; try with -l level_name"
                exit 1
            fi
            ;;
        *)
            echo "Error: bad arguments; try with -l level_name"
            exit 1
            ;;
    esac
else
    echo "Error: bad arguments; try with -l level_name"
    exit 1
fi