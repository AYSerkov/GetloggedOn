# Базовая проверка одного хоста
python GetloggedOn.py administrator:pass@192.168.1.10

# С файлом хостов и 2 потоками
python GetloggedOn.py --threads 2 user:pass@ --host-file hosts.txt

# С аутентификацией по хешам
python GetloggedOn.py -hashes LMHASH:NTHASH admin@10.10.10.5

# Kerberos-аутентификация
python GetloggedOn.py -k -dc-ip 192.168.1.1 user:pass@domain/DC01
