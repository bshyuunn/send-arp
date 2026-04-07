### Demo

왼쪽 터미널은 Mac(Victim)이고, 오른쪽 터미널은 같은 네트워크에 있는 Linux(Attacker)에 SSH로 연결한 모습입니다. Attacker가 send-arp를 실행하면 Victim의 ARP 테이블이 변조되어 ping이 끊기고, tcpdump에서 Victim의 ICMP 패킷이 잡히는 것을 확인할 수 있습니다.

![](./send-arp-demo.mp4)
