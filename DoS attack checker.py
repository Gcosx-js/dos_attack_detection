import time
from collections import deque
from scapy.all import *


def DoS_yoxlama(pkt_threshold=100, her_saniye=1):
    pkt_say = 0
    pkt_siyahisi = deque(maxlen=pkt_threshold)
    baslangic_vaxti = time.time()
    cari_tehluke = None
    
    # Cari vaxtın çap edilməsi
    now = datetime.now()
    current_time = now.strftime("%H:%M:%S")
    print("Cari vaxt : ", current_time)
    s= 0
    
    # Şəbəkədə təhlükəni yoxlamaq üçün dövr
    while True:
        pkt = sniff(count=1)
        cari_vaxt_ = time.time()
        
        pkt_say += 1
        pkt_siyahisi.append((pkt[0][1].src, cari_vaxt_))
        pkt_siyahisi = deque([x for x in pkt_siyahisi if cari_vaxt_ - x[1] < her_saniye], maxlen=pkt_threshold)
        
        # Saldırı tespiti
        if pkt_say >= pkt_threshold and len(set([x[0] for x in pkt_siyahisi])) == 1:
            if not cari_tehluke:
                print("DoS təhlükəsi aşkar edildi!")
                cari_tehluke = True
                break
        else:
            s +=1
            cari_tehluke = False # Əgər təhlükə aşkar edilməzsə bunu bildir
            print(f"DoS təhlükəsi aşkar edilmədi!({s})")

        
        # Hər saniyədən sonra yenidən hesablamaq üçün
        if cari_vaxt_ - baslangic_vaxti > her_saniye:
            pkt_say = 0
            pkt_siyahisi.clear()
            baslangic_vaxti = cari_vaxt_
            cari_tehluke = False

if __name__ == '__main__':
    DoS_yoxlama()
