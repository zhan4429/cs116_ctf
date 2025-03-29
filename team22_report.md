# 2025 CTF Report from Team 22

- Chris Talavera
- Jackson Xu
- Joel Han
- Yucheng Zhang

## Unsolved chanllenges:

- Challenge 4: All your base64 are belong to us. 

- Challenge 9: Buried in the dump, redux: needle in the haystack. 

- Challenge 13: LOLCAP.

- Challenge 14: notuber. 



## Challenge 1: ROTten to the Core (Yucheng Zhang). 

### Problem

```
Gubfr bs lbh jub ner gnxvat pbzchgre fpvrapr pynffrf va fpubby znl ng guvf
cbvag or guvaxvat, bx, jr’ir tbg guvf fbegrq. Jr’er nyernql orvat gnhtug nyy
nobhg cebtenzzvat. Ohg fbeel, guvf vf abg rabhtu. Lbh unir gb or jbexvat ba
lbhe bja cebwrpgf, abg whfg yrneavat fghss va pynffrf. Lbh pna qb jryy va
pbzchgre fpvrapr pynffrf jvgubhg rire ernyyl yrneavat gb cebtenz. Va snpg
lbh pna tenqhngr jvgu n qrterr va pbzchgre fpvrapr sebz n gbc havirefvgl
naq fgvyy abg or nal tbbq ng cebtenzzvat. Gung’f jul grpu pbzcnavrf nyy
znxr lbh gnxr n pbqvat grfg orsber gurl’yy uver lbh, ertneqyrff bs jurer
lbh jrag gb havirefvgl be ubj jryy lbh qvq gurer. Gurl xabj tenqrf naq
rknz erfhygf cebir abguvat.
xrl{4n247351p63n867os26q505q095p37284rsp3802087onpnp363n418184pp7506}
uggcf://cnhytenunz.pbz/tbbtyr.ugzy
```

### Solution

The code is ROT13-encoded message. I used rot13-decoder (https://cryptii.com/pipes/rot13-decoder) to decode the text, and key `key{4a247351c63a867bf26d505d095c37284efc3802087bacac363a418184cc7506}` is revealed

<img src="rotten.png" alt="Rotten Image" width="70%">

## Challenge 2: I hope I didn't make this too easy: another flag is on the blog.

### Problem

Xxxxx

### Solution

This is a multi-layer Base64 encoded text. I used the below python script to decode 20 layers to finally got the key `key{5925189030bc2af596c7ccc8d925c292ca0e25165965caba71e9d5fafaebd744}`.

```
import base64

# Read the input
data = open("encoded.txt", "rb").read()

# Try decoding up to 50 layers
for i in range(50):
    try:
        print(f"[+] Decoding layer {i+1}")
        data = base64.b64decode(data)
    except Exception as e:
        print(f"[-] Stopped decoding at layer {i+1}: {e}")
        break

# Save final decoded data
with open("decoded_final.bin", "wb") as f:
    f.write(data)
```

## Challenge 3: .git the FLAG. 



## Challenge 5: Don't ask me if something looks wrong. Look again, pay careful attention. 



## Challenge 6: Don't ask me if something looks wrong. Look again, pay really careful attention.



## Challenge 7: That readme is peculiar...





## Challenge 8: A whole bunch of CS40 homeworks found

![cs40 flag](cs40_flag.png)





## Challenge 10: About my friend bobo

# ![bobo flag](bobo_flag.png)



## Challenge 11: XSS gone sinister. 

## Challenge 12: Where are the robots? (Yucheng Zhang)
