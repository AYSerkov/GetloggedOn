# Базовая проверка одного хоста
python GetloggedOn.py administrator:pass@192.168.1.10

# С файлом хостов и 2 потоками (дефолт в 1 поток, лучше в 1)
python GetloggedOn.py --threads 2 domain.local/user:pass@ --host-file hosts.txt

# С аутентификацией по хешам
python GetloggedOn.py -hashes LMHASH:NTHASH domain.local/user:pass@10.10.10.5

# Kerberos-аутентификация
python GetloggedOn.py -k -dc-ip 192.168.1.1 domain.local/user:pass@domain/DC01
