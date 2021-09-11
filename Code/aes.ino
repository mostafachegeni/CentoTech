#include <AES.h>

AES aes;

byte *key = (unsigned char*)"0123456789010123";

byte plain[] = "Add NodeAdd NodeAdd NodeAdd NodeAdd Node";
int plainLength = sizeof(plain)-1;  // don't count the trailing /0 of the string !
int padedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;

//real iv = iv x2 ex: 01234567 = 0123456701234567
//unsigned long long int my_iv = 36753562;
unsigned long long int my_iv = 0;

void setup ()
{
  Serial.begin (57600);
  while (!Serial) {
    ; // wait for serial port to connect. Needed for Leonardo only
  }
//  printf_begin();
  delay(500);
  printf("\n===testing mode\n") ;

//  otfly_test () ;
//  otfly_test256 () ;
}

void loop () 
{
//  prekey_test () ;
  delay(2000);

  String Location = "OK12345677654321";
  byte plain[17];
  Location.getBytes(plain, 17);
  Serial.println(Location);
  Serial.print("Plain: ");
  for(int i=0; i<17; i++){
    Serial.print(plain[i], HEX);    
  }
  Serial.println();    

  int bits = 128;
  int plainLength = sizeof(plain)-1;  // don't count the trailing /0 of the string !
  int padedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;
  aes.iv_inc();
  byte iv [N_BLOCK] ;
  byte plain_p[16];
  byte cipher [16];
  byte check [16];
  aes.set_IV(my_iv);
  aes.get_IV(iv);

  for(int i=0; i<16; i++){
    plain_p[i] = plain[i];
  }
  aes.do_aes_encrypt(plain_p, 16, cipher, key, bits, iv);

  Serial.println("PLAIN: ");
  aes.printArray(plain,16);
  Serial.print("CIPHER: ");
  aes.printArray(cipher,16);
  
}

void prekey (int bits)
{
  aes.iv_inc();
  byte iv [N_BLOCK] ;
  byte plain_p[padedLength];
  byte cipher [padedLength] ;
  byte check [padedLength] ;
  unsigned long ms = micros ();
  aes.set_IV(my_iv);
  aes.get_IV(iv);
  aes.do_aes_encrypt(plain,plainLength,cipher,key,bits,iv);
  Serial.print("Encryption took: ");
  Serial.println(micros() - ms);
  ms = micros ();
  aes.set_IV(my_iv);
  aes.get_IV(iv);
  aes.do_aes_decrypt(cipher,padedLength,check,key,bits,iv);
  Serial.print("Decryption took: ");
  Serial.println(micros() - ms);
  Serial.println("\n\nPLAIN :");
//  aes.printArray(plain,(bool)true);
  aes.printArray(plain,16);
  Serial.println("\nCIPHER:");
//  aes.printArray(cipher,(bool)false);
//  aes.printArray(cipher,(bool)true);
  aes.printArray(cipher,16);
  Serial.println("\nCHECK :");
//  aes.printArray(check,(bool)true);
  aes.printArray(check,16);
  Serial.println("\nIV    :");
  aes.printArray(iv,16);
  Serial.println("\n============================================================\n");
}

void prekey_test ()
{
  prekey (128) ;
}
