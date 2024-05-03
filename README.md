```
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
```

**LocalNetScan** - данная программа проверяет существование устройства по IP в локальной сети. Также можно указать диапозон IP, тогда получится сканер локальной сети : D. Обязательно вместе с `.exe` или `.py` файлом должен быть файл `localnetscan-config.json`, иначе ничего работать не будет. Но если данного файла нету рядом с программой, то программа сама его создаст. В файле конфигурации 3 пункта:

```
{                                                                                              
    "timeout": [время в секундах (целое число)], <- отвечает за время ожидания ответа устройства/устройств.  
    "writeDataInJson": true/false, <- отвечает за запись выходных данных в json файл.          
    "logo": true/false <- отвечает за вывод логотипа после запуска программы.                  
}
```

В поле, где просят указать IP, можно ввести `help`, тогда вызовется справка.

Ещё забыл сказать, для проги надо установить **scapy**: `pip install scapy`

***

### Хотите внести свой вклад в проект? - читайте [CONTRIBUTING.md](CONTRIBUTING.md)

***