#! /usr/bin/env python
logo = '''\033[92m
                                                       _____
    __         ______   ______   ________  __          |   |               ___   ___  ________  ____________
    | |       /  __  \ /  ____| /  ____  \ | |         ¯¯|¯¯        _____  |  \  |  | |  _____| |____  ____|
    | |       | |  | | | |      | |____| | | |          ¯¯¯\    ___/|   |  |   \ |  | |  |____       | |
    | |       | |  | | | |      |  ____  | | |             /\  /    ¯¯|¯¯  |    \|  | |  _____|      | |  
    | |       | |  | | | |      | |    | | | |            /  ¯¯¯\    ¯¯¯   |  |\    | |  |____       | |
    | |_____  | |__| | | |____  | |    | | | |_____      /       ¯_____    |  | \   | |       |      | |
    |_______| \______/ \______| |_|    |_| |_______|  _____       |   |    |__|  \__| |_______|      |_| SCAN
                                                      |   |       ¯¯|¯¯
                                                      ¯¯|¯¯        ¯¯¯
                                                       ¯¯¯
\033[0m''' 
#                                           ! ВНИМАНИЕ !                                             #
#                                                                                                    #
#               ДАННАЯ ПРОГРАММА СКАНИРУЕТ IP АДРЕС/АДРЕСА ТОЛЬКО В ЛОКАЛЬНОЙ СЕТИ                   #
#                              В КОТОРОМ НАХОДИТСЯ САМА ПРОГРАММА                                    #
#                                                                                                    #
#  localnetscan - данная программа проверяет существование устройства по IP в локальной сети.        #
#  Также можно указать диапозон IP, тогда получится сканер локальной сети :). Обязательно вместе     #
#  с .exe или .py файлом должен быть файл localnetscan-config.json, иначе ничего работать не будет.  #
#  В файле конфигурации 3 пункта:                                                                    #
#  {                                                                                                 #
#      "timeout": [время в секундах], <- отвечает за время ожидания ответа устройства/устройств.     #
#      "writeDataInJson": true/false, <- отвечает за запись выходных данных в json файл.             #
#      "logo": true/false <- отвечает за вывод логотипа после запуска программы.                     #
#  }                                                                                                 #
#                            ! в пункте timeout указывать полное число !                             #
#                                                                                                    #
#  В поле, где просят указать IP, можно ввести help, тогда вызовется справка.                        #
#                                                                                                    #
#  (простите за корявое описание (если оно таковым и яляется)                                        # 

import scapy.all as scapy
import json

try:
    with open('localnetscan-config.json','r') as file:
        configFile = json.load(file)
except FileNotFoundError:
    configFileData = {
        "timeout": 10,
        "writeDataInJson": False,
        "logo": True
    }
    print('\n['+'\033[91m'+'-'+'\033[0m'+'] Файл'+'\033[93m '+'localnetscan-config.json'+'\033[0m'+' не найден')
    print('[...] Создание файла конфигурации')
    with open('localnetscan-config.json','w') as createConfigFile:
        json.dump(configFileData, createConfigFile, indent=4)

    input('['+'\033[92m'+'+'+'\033[0m'+'] Файл конфигурации \033[93mlocalnetscan-config.json\033[0m успешно создан')
    exit()
except json.decoder.JSONDecodeError:
    input('\n['+'\033[91m'+'-'+'\033[0m'+'] Неверное значение в'+'\033[93m '+'localnetscan-config.json'+'\033[0m')
    exit()
if configFile["logo"] is True:
    print(logo)
elif configFile["logo"] is False:
    pass
else:
    pass

targetIP = input('Укажите ip или его диапозон -> ')

if targetIP == 'help':
    input('''
В строке, где просят ввести IP или его диапозон, надо ввести ip адрес целовой машины
(например: 1.1.1.1). Если укажите диапозон IP адресов, то программа просканирует
все возможные ip адреса, указанные в диапозоне (например: 1.1.1.1/24 - просканируются
IP адреса 1.1.1.0, 1.1.1.1, 1.1.1.2 и тд до 1.1.1.255).
          
После завершения работы программа выводит IP и MAC адрес отвеченных машин (пример:
          
     IP                    MAC
-------------------------------------
1.1.1.1             00:11:22:33:44:55
          
)
          
В файле конфигурации localnetscan-config.json 3 пункта:                                                                 
{                                                                                              
    "timeout": [время в секундах], <- отвечает за время ожидания ответа устройства/устройств.  
    "writeDataInJson": true/false, <- отвечает за запись выходных данных в json файл.          
    "logo": true/false <- отвечает за вывод логотипа после запуска программы.                  
}             
                                                                                           
! в пункте timeout указывать полное число !
''')
    exit()

def _netscan(ip):
    try:
        print('\n[...] Сканирование')
        print(f'[*] Ожидание: {configFile["timeout"]} c.')
        print(f'[*] Запись полученных данных в json файл: {configFile["writeDataInJson"]}')
        print('['+'\033[93m'+'i'+'\033[0m'+'] Список может выводиться не с 1-ого раза в зависимости от указанного ожидания в файле '+'\033[93m'+'localnetscan-config.json'+'\033[0m')
        arpRequest = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        request = broadcast/arpRequest
        try:
            answered = scapy.srp(request, timeout=configFile["timeout"], verbose=False)[0]
        except TypeError:
            input('\n['+'\033[91m'+'-'+'\033[0m'+'] Неверное значение в файле '+'\033[93m'+'localnetscan-config.json'+'\033[0m')
            exit()
        print('\n     IP\t\t           MAC\n-------------------------------------')
        clients = []
        for answeredClients in answered:
            answeredClientsDict = {"ip":answeredClients[1].psrc, "mac":answeredClients[1].hwsrc}
            clients.append(answeredClientsDict)
            print(answeredClients[1].psrc+'\t    '+answeredClients[1].hwsrc)
        if configFile["writeDataInJson"] is True:
            with open('localnetscan-output-data.json','w') as file:
                json.dump(clients, file, indent=4)
                input('\n['+'\033[92m'+'+'+'\033[0m'+'] Данные успешно записаны в '+'\033[93m'+'localnetscan-config.json'+'\033[0m')
        elif configFile["writeDataInJson"] is False:
            input()
            exit()
        else:
            exit()
    except PermissionError:
        input('\n['+'\033[91m'+'-'+'\033[0m'+'] Скрипт выполняется от'+'\033[93m '+'root'+'\033[0m')

_netscan(targetIP)
