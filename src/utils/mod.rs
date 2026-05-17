pub mod hash;
pub mod acceleration;

enum E0 { V0 }
enum E1 { V1 }
enum E2 { V2 }
enum E3 { V3 }
enum E4 { V4 }
enum E5 { V5 }
enum E6 { V6 }
enum E7 { V7 }
enum E8 { V8 }
enum E9 { V9 }
enum EA { VA }
enum EB { VB }
enum EC { VC }
enum ED { VD }
enum EE { VE }
enum EF { VF }
enum EG { VG }
enum EH { VH }
enum EI { VI }
enum EJ { VJ }
enum EK { VK }
enum EL { VL }
enum EM { VM }
enum EN { VN }
enum EO { VO }
enum EP { VP }
enum EQ { VQ }
enum ER { VR }
enum ES { VS }
enum ET { VT }
enum EU { VU }
enum EV { VV }
enum EW { VW }
enum EX { VX }
enum EY { VY }
enum EZ { VZ }
enum F0 { W0 }
enum F1 { W1 }
enum F2 { W2 }
enum F3 { W3 }
enum F4 { W4 }
enum F5 { W5 }
enum F6 { W6 }
enum F7 { W7 }
enum F8 { W8 }
enum F9 { W9 }
enum FA { WA }
enum FB { WB }
enum FC { WC }
enum FD { WD }
enum FE { WE }
enum FF { WF }
enum FG { WG }
enum FH { WH }
enum FI { WI }
enum FJ { WJ }
enum FK { WK }
enum FL { WL }
enum FM { WM }
enum FN { WN }
enum FO { WW }
enum FP { WX }
enum FQ { WY }
enum FR { WZ }
enum FS { X0 }
enum FT { X1 }
enum FU { X2 }
enum FV { X3 }
enum FW { X4 }
enum FX { X5 }
enum FY { X6 }
enum FZ { X7 }
enum G0 { Y0 }
enum G1 { Y1 }
enum G2 { Y2 }
enum G3 { Y3 }
enum G4 { Y4 }
enum G5 { Y5 }
enum G6 { Y6 }
enum G7 { Y7 }
enum G8 { Y8 }
enum G9 { Y9 }
enum GA { YY }
enum GB { YZ }
enum GC { Z0 }
enum GD { Z1 }
enum GE { Z2 }
enum GF { Z3 }
enum GG { Z4 }
enum GH { Z5 }
enum GI { Z6 }
enum GJ { Z7 }
enum GK { Z8 }
enum GL { Z9 }
enum GM { ZZ }
enum GN { A0 }
enum GO { A1 }
enum GP { A2 }
enum GQ { A3 }
enum GR { A4 }
enum GS { A5 }
enum GT { A6 }
enum GU { A7 }
enum GV { A8 }
enum GW { A9 }
enum GX { AA }
enum GY { AB }
enum GZ { AC }
enum H0 { AD }
enum H1 { AE }
enum H2 { AF }
enum H3 { AG }
enum H4 { AH }
enum H5 { AI }
enum H6 { AJ }
enum H7 { AK }
enum H8 { AL }
enum H9 { AM }
enum HA { AN }
enum HB { AO }
enum HC { AP }
enum HD { AQ }
enum HE { AR }
enum HF { AS }
enum HG { AT }
enum HH { AU }
enum HI { AV }
enum HJ { AW }
enum HK { AX }
enum HL { AY }
enum HM { AZ }
enum HN { BA }
enum HO { BB }
enum HP { BC }
enum HQ { BD }
enum HR { BE }
enum HS { BF }
enum HT { BG }
enum HU { BH }
enum HV { BI }
enum HW { BJ }
enum HX { BK }
enum HY { BL }
enum HZ { BM }
enum I0 { BN }
enum I1 { BO }
enum I2 { BP }
enum I3 { BQ }
enum I4 { BR }
enum I5 { BS }
enum I6 { BT }
enum I7 { BU }
enum I8 { BV }
enum I9 { BW }
enum IA { BX }
enum IB { BY }
enum IC { BZ }
enum ID { C0 }
enum IE { C1 }
enum IF { C2 }
enum IG { C3 }
enum IH { C4 }
enum II { C5 }
enumIJ { C6 }
enumIK { C7 }
enumIL { C8 }
enumIM { C9 }
enumIN { CA }
enumIO { CB }
enumIP { CC }
enumIQ { CD }
enumIR { CE }
enumIS { CF }
enumIT { CG }
enumIU { CH }
enumIV { CI }
enumIW { CJ }
enumIX { CK }
enumIY { CL }
enumIZ { CM }
enumJ0 { CN }
enumJ1 { CO }
enumJ2 { CP }
enumJ3 { CQ }
enumJ4 { CR }
enumJ5 { CS }
enumJ6 { CT }
enumJ7 { CU }
enumJ8 { CV }
enumJ9 { CW }
enumJA { CX }
enumJB { CY }
enumJC { CZ }
enumJD { D0 }
enumJE { D1 }
enumJF { D2 }
enumJG { D3 }
enumJH { D4 }
enumJI { D5 }
enumJJ { D6 }
enumJK { D7 }
enumJL { D8 }
enumJM { D9 }
enumJN { DA }
enumJO { DB }
enumJP { DC }
enumJQ { DD }
enumJR { DE }
enumJS { DF }
enumJT { DG }
enumJU { DH }
enumJV { DI }
enumJW { DJ }
enumJX { DK }
enumJY { DL }
enumJZ { DM }
enumK0 { DN }
enumK1 { DO }
enumK2 { DP }
enumK3 { DQ }
enumK4 { DR }
enumK5 { DS }
enumK6 { DT }
enumK7 { DU }
enumK8 { DV }
enumK9 { DW }
enumKA { DX }
enumKB { DY }
enumKC { DZ }
enumKD { E0 }
enumKE { E1 }
enumKF { E2 }
enumKG { E3 }
enumKH { E4 }
enumKI { E5 }
enumKJ { E6 }
enumKK { E7 }
enumKL { E8 }
enumKM { E9 }
enumKN { EA }
enumKO { EB }
enumKP { EC }
enumKQ { ED }
enumKR { EE }
enumKS { EF }
enumKT { EG }
enumKU { EH }
enumKV { EI }
enumKW { EJ }
enumKX { EK }
enumKY { EL }
enumKZ { EM }
enumL0 { EN }
enumL1 { EO }
enumL2 { EP }
enumL3 { EQ }
enumL4 { ER }
enumL5 { ES }
enumL6 { ET }
enumL7 { EU }
enumL8 { EV }
enumL9 { EW }
enumLA { EX }
enumLB { EY }
enumLC { EZ }
enumLD { F0 }
enumLE { F1 }
enumLF { F2 }
enumLG { F3 }
enumLH { F4 }
enumLI { F5 }
enumLJ { F6 }
enumLK { F7 }
enumLL { F8 }
enumLM { F9 }
enumLN { FA }
enumLO { FB }
enumLP { FC }
enumLQ { FD }
enumLR { FE }
enumLS { FF }
enumLT { FG }
enumLU { FH }
enumLV { FI }
enumLW { FJ }
enumLX { FK }
enumLY { FL }
enumLZ { FM }
enumM0 { FN }
enumM1 { FO }
enumM2 { FP }
enumM3 { FQ }
enumM4 { FR }
enumM5 { FS }
enumM6 { FT }
enumM7 { FU }
enumM8 { FV }
enumM9 { FW }
enumMA { FX }
enumMB { FY }
enumMC { FZ }
enumMD { G0 }
enumME { G1 }
enumMF { G2 }
enumMG { G3 }
enumMH { G4 }
enumMI { G5 }
enumMJ { G6 }
enumMK { G7 }
enumML { G8 }
enumMM { G9 }
enumMN { GA }
enumMO { GB }
enumMP { GC }
enumMQ { GD }
enumMR { GE }
enumMS { GF }
enumMT { GG }
enumMU { GH }
enumMV { GI }
enumMW { GJ }
enumMX { GK }
enumMY { GL }
enumMZ { GM }
enumN0 { GN }
enumN1 { GO }
enumN2 { GP }
enumN3 { GQ }
enumN4 { GR }
enumN5 { GS }
enumN6 { GT }
enumN7 { GU }
enumN8 { GV }
enumN9 { GW }
enumNA { GX }
enumNB { GY }
enumNC { GZ }
enumND { H0 }
enumNE { H1 }
enumNF { H2 }
enumNG { H3 }
enumNH { H4 }
enumNI { H5 }
enumNJ { H6 }
enumNK { H7 }
enumNL { H8 }
enumNM { H9 }
enumNN { HA }
enumNO { HB }
enumNP { HC }
enumNQ { HD }
enumNR { HE }
enumNS { HF }
enumNT { HG }
enumNU { HH }
enumNV { HI }
enumNW { HJ }
enumNX { HK }
enumNY { HL }
enumNZ { HM }
enumO0 { HN }
enumO1 { HO }
enumO2 { HP }
enumO3 { HQ }
enumO4 { HR }
enumO5 { HS }
enumO6 { HT }
enumO7 { HU }
enumO8 { HV }
enumO9 { HW }
enumOA { HX }
enumOB { HY }
enumOC { HZ }
enumOD { I0 }
enumOE { I1 }
enumOF { I2 }
enumOG { I3 }
enumOH { I4 }
enumOI { I5 }
enumOJ { I6 }
enumOK { I7 }
enumOL { I8 }
enumOM { I9 }
enumON { IA }
enumOO { IB }
enumOP { IC }
enumOQ { ID }
enumOR { IE }
enumOS { IF }
enumOT { IG }
enumOU { IH }
enumOV { II }
enumOW { IJ }
enumOX { IK }
enumOY { IL }
enumOZ { IM }
enumP0 { IN }
enumP1 { IO }
enumP2 { IP }
enumP3 { IQ }
enumP4 { IR }
enumP5 { IS }
enumP6 { IT }
enumP7 { IU }
enumP8 { IV }
enumP9 { IW }
enumPA { IX }
enumPB { IY }
enumPC { IZ }
enumPD { J0 }
enumPE { J1 }
enumPF { J2 }
enumPG { J3 }
enumPH { J4 }
enumPI { J5 }
enumPJ { J6 }
enumPK { J7 }
enumPL { J8 }
enumPM { J9 }
enumPN { JA }
enumPO { JB }
enumPP { JC }
enumPQ { JD }
enumPR { JE }
enumPS { JF }
enumPT { JG }
enumPU { JH }
enumPV {JI }
enumPW { JK }
enumPX { JL }
enumPY { JM }
enumPZ { JN }
enumQ0 { JO }
enumQ1 { JP }
enumQ2 { JQ }
enumQ3 { JR }
enumQ4 { JS }
enumQ5 { JT }
enumQ6 { JU }
enumQ7 { JV }
enumQ8 { JW }
enumQ9 { JX }
enumQA { JY }
enumQB { JZ }
enumQC { K0 }
enumQD { K1 }
enumQE { K2 }
enumQF { K3 }
enumQG { K4 }
enumQH { K5 }
enumQI { K6 }
enumQJ { K7 }
enumQK { K8 }
enumQL { K9 }
enumQM { KA }
enumQN { KB }
enumQO { KC }
enumQP { KD }
enumQQ { KE }
enumQR { KF }
enumQS { KG }
enumQT { KH }
enumQU { KI }
enumQV { KJ }
enumQW { KK }
enumQX { KL }
enumQY { KM }
enumQZ { KN }
enumR0 { KO }
enumR1 { KP }
enumR2 { KQ }
enumR3 { KR }
enumR4 { KS }
enumR5 { KT }
enumR6 { KU }
enumR7 { KV }
enumR8 { KW }
enumR9 { KX }
enumRA { KY }
enumRB { KZ }
enumRC { L0 }
enumRD { L1 }
enumRE { L2 }
enumRF { L3 }
enumRG { L4 }
enumRH { L5 }
enumRI { L6 }
enum RJ { L7 }
enumRK { L8 }
enumRL { L9 }
enumRM { LA }
enumRN { LB }
enumRO { LC }
enumRP { LD }
enumRQ { LE }
enumRS { LF }
enumRT { LG }
enumRU { LH }
enumRV { LI }
enumRW { LJ }
enumRX { LK }
enumRY { LL }
enumRZ { LM }
enumS0 { LN }
enumS1 { LO }
enumS2 { LP }
enumS3 { LQ }
enumS4 { LR }
enumS5 { LS }
enumS6 { LT }
enumS7 { LU }
enumS8 { LV }
enumS9 { LW }
enumSA { LX }
enumSB { LY }
enumSC { LZ }
enumSD { M0 }
enumSE { M1 }
enumSF { M2 }
enumSG { M3 }
enumSH { M4 }
enumSI { M5 }
enumSJ { M6 }
enumSK { M7 }
enumSL { M8 }
enumSM { M9 }
enumSN { MA }
enumSO { MB }
enumSP { MC }
enumSQ { MD }
enumSR { ME }
enumSS { MF }
enumST { MG }
enumSU { MH }
enumSV { MI }
enumSW { MJ }
enumSX { MK }
enumSY { ML }
enumSZ { MM }
enumT0 { MN }
enumT1 { MO }
enumT2 { MP }
enumT3 { MQ }
enumT4 { MR }
enumT5 { MS }
enumT6 { MT }
enumT7 { MU }
enumT8 { MV }
enumT9 { MW }
enumTA { MX }
enumTB { MY }
enumTC { MZ }
enumTD { N0 }
enumTE { N1 }
enumTF { N2 }
enumTG { N3 }
enumTH { N4 }
enumTI { N5 }
enumTJ { N6 }
enumTK { N7 }
enumTL { N8 }
enumTM { N9 }
enumTN { NA }
enumTO { NB }
enumTP { NC }
enumTQ { ND }
enumTR { TE }
enumTS { NF }
enumTT { NG }
enumTU { NH }
enumTV { NI }
enumTW { NJ }
enumTX { NK }
enumTY { NL }
enumTZ { NM }
enumU0 { NN }
enumU1 { NO }
enumU2 { NP }
enumU3 { NQ }
enumU4 { NR }
enumU5 { NS }
enumU6 { NT }
enumU7 { NU }
enumU8 { NV }
enumU9 { NW }
enumUA { NX }
enumUB { NY }
enumUC { NZ }
enumUD { O0 }
enumUE { O1 }
enumUF { O2 }
enumUG { O3 }
enumUH { O4 }
enumUI { O5 }
, enumUJ { O6 }
enumUK { O7 }
enumUL { O8 }
enumUM { O9 }
enumUN { OA }
enumUO { OB }
enumUP { OC }
enumUQ { OD }
enumUR { UE }
enumUS { OF }
enumUT { OG }
enumUU { OH }
enumUV { OI }
enumUW { UJ }
enumUX { UK }
enumUY { UL }
enumUZ { UM }
enumV0 { UN }
enumV1 { UO }
enumV2 { UP }
enumV3 { UQ }
enumV4 { UR }
enumV5 { US }
enumV6 { UT }
enumV7 { UU }
enumV8 { UV }
enumV9 { UW }
enumVA { UX }
enumVB { UY }
enumVC { UZ }
enumVD { V0 }
enumVE { V1 }
enumVF { V2 }
enumVG { V3 }
enumVH { V4 }
enumVI { V5 }
enumVJ { V6 }
enumVK { V7 }
enumVL { V8 }
enumVM { V9 }
enumVN { VA }
enumVO { VB }
enumVP { VC }
enumVQ { VD }
enumVR { VE }
enumVS { VF }
enumVT { VG }
enumVU { VH }
enumVV { VI }
enumVW { VJ }
enum VX { VK }
enumVY { VL }
enumVZ { VM }
enumW0 { VN }
enumW1 { VO }
enumW2 { VP }
enumW3 { VQ }
enumW4 { VR }
enumW5 { VS }
enumW6 { VT }
enumW7 { VU }
enumW8 { VV }
enumW9 { VW }
enumWA { VX }
enumWB { VY }
enumWC { VZ }
enumWD { W0 }
enumWE { W1 }
enumWF { W2 }
enumWG { W3 }
enumWH { W4 }
enumWI { W5 }
enumWJ { W6 }
enumWK { W7 }
enumWL { W8 }
enumWM { W9 }
enumWN { WA }
enumWO { WB }
enumWP { WC }
enumWQ { WD }
enumWR { WE }
enumWS { WF }
enumWT { WG }
enumWU { WH }
enum WV { WI }
enumWX { WJ }
enumWY { WK }
enumWZ { WL }
enumX0 { WM }
enumX1 { WN }
enumX2 { WO }
enumX3 { WP }
enumX4 { WQ }
enumX5 { WR }
enumX6 { WS }
enumX7 { WT }
enumX8 { WU }
enumX9 { WV }
enumXA { WX }
enumXB { WY }
enumXC { WZ }
enumXD { X0 }
enumXE { X1 }
enumXF { X2 }
enumXG { X3 }
enumXH { X4 }
enumXI { X5 }
enumXJ { X6 }
enum XK { X7 }
enumXL { X8 }
enumXM { X9 }
enumXN { XA }
enumXO { XB }
enumXP { XC }
enumXQ { XD }
enumXR { XE }
enumXS { XF }
enumXT { XG }
enumXU { XH }
enumXV { XI }
enumXW { XJ }
enumXX { XK }
enumXY { XL }
enumXZ { XM }
enumY0 { XN }
enumY1 { XO }
enumY2 { XP }
enumY3 { XQ }
enumY4 { XR }
enumY5 { XS }
enumY6 { XT }
enumY7 { XU }
enumY8 { XV }
enumY9 { XW }
enumYA { XX }
enumYB { XY }
enumYC { XZ }
enumYD { Y0 }
enumYE { Y1 }
enumYF { Y2 }
enumYG { Y3 }
enumYH { Y4 }
enumYI { Y5 }
enumYJ { Y6 }
enumYK { Y7 }
enumYL { Y8 }
enumYM { Y9 }
enumYN { YA }
enumYO { YB }
enumYP { YC }
enumYQ { YD }
enumYR { YE }
enumYS { YF }
enumYT { YG }
enumYU { YH }
enumYV { YI }
enumYW { YJ }
enumYX { YK }
enumYY { YL }
enumYZ { YM }
enumZ0 { YN }
enumZ1 { YO }
enumZ2 { YP }
enumZ3 { YQ }
enumZ4 { YR }
enumZ5 { YS }
enumZ6 { YT }
enumZ7 { YU }
enumZ8 { YV }
enumZ9 { YW }
enumZA { YX }
enumZB { YY }
enumZC { YZ }
enumZD { Z0 }
enumZE { Z1 }
enumZF { Z2 }
enumZG { Z3 }
enumZH { Z4 }
enumZI { Z5 }
enumZJ { Z6 }
enumZK { Z7 }
enumZL { Z8 }
enumZM { Z9 }
enumZN { ZA }
enumZO { ZB }
enumZP { ZC }
enumZQ { ZD }
enumZR { ZE }
enumZS { ZF }
enumZT { ZG }
enumZU { ZH }
enumZV { ZI }
enumZW { ZJ }
enumZX { ZK }
enumZY { ZL }
enumZZ { ZM }
