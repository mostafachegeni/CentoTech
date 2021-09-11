#include <ESP8266WiFi.h>
#include <AES.h>
#include "FS.h"

//ADC:
//ADC Set Mode
ADC_MODE(ADC_VCC);

#define OK_From_MC60           0
#define No_Response_From_MC60  1
#define Error_From_MC60        2

#define OK_Send_SMS            0
#define NULL                   ""

#define PIN_ESP_LED            2
#define PIN_PWRKEY            14

AES m_aes;
void AES_Encrypt_CBC(unsigned char* Plaintext, byte* Ciphertext, byte* Key, int Input_Number_of_Blocks)
{
  byte Last_Encrypted_Block [16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
  byte input_block_byte [16];
  
  for(int i=0; i<Input_Number_of_Blocks; i++){
    for(int j=0; j<16; j++){
      input_block_byte[j] = Plaintext[j+16*i] ^ Last_Encrypted_Block[j];
    }
    
    AES_Encrypt_ECB_byteInput(input_block_byte, Last_Encrypted_Block, Key);
    
    for(int j=0; j<16; j++){
      Ciphertext[j+16*i] = Last_Encrypted_Block[j];
    }
  }
}

//Length of "Plaintext" must be 16 bytes.
//Length of "Ciphertext" is 16 bytes.
void AES_Encrypt_ECB_byteInput(byte* Plaintext, byte* Ciphertext, byte* Key)
{
  int bits = 128;
  byte* key;
  byte* input_byte;
  key = Key;
  input_byte = Plaintext;
  
  int plainLength = 16;
  int padedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;
  byte output_byte [padedLength] ;

  unsigned long long int my_iv = 0;
  byte iv [N_BLOCK] ;
  m_aes.iv_inc();
  m_aes.set_IV(my_iv);
  m_aes.get_IV(iv);

  m_aes.do_aes_encrypt(input_byte, plainLength, output_byte, key, bits, iv);

  for(int i=0; i<16; i++){
    Ciphertext[i] = output_byte[i];      
  }
  return;
}

//Length of "Plaintext" must be 16.
//Length of "Ciphertext" is 16.
void AES_Encrypt_ECB_stringInput(String Plaintext, byte* Ciphertext, byte* Key)
{
  if(Plaintext.length() != 16) {
    byte output_byte[] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0}; 
    for(int i=0; i<16; i++){
      Ciphertext[i] = output_byte[i];      
    }
    return;
  } else {
    int bits = 128;
    byte* key;
    key = Key;
    
    byte input_byte[17];
    Plaintext.getBytes(input_byte, 17);

    int plainLength = sizeof(input_byte)-1;  // don't count the trailing /0 of the string !
    int padedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;
    byte output_byte [padedLength] ;

    unsigned long long int my_iv = 0;
    byte iv [N_BLOCK] ;
    m_aes.iv_inc();
    m_aes.set_IV(my_iv);
    m_aes.get_IV(iv);

    m_aes.do_aes_encrypt(input_byte, plainLength, output_byte, key, bits, iv);

    for(int i=0; i<16; i++){
      Ciphertext[i] = output_byte[i];      
    }
    return;
  }
}


void Send_TCP()
{
  /*
  // GPRS + TCP/IP:
  AT+CGATT=1    // Attach to GPRS Service
  AT+CGACT=1    // Activate PDP context
  AT+QIDNSIP=1  // Use "domain name" as the address to establish TCP session, AT+QIDNSIP=0 : IP
  GSM_command("AT+QIREGAPP=\"mtnirancell\",\"\",\"\"");    // Start TCPIP Task; apn=mtnirancell, user=<NULL>, pass=<NULL>
  GSM_command("AT+QIACT");    // Activate GPRS Context
  GSM_command("AT+QNTP=\"2.ir.pool.ntp.org\""); //  Default SERVER: 210.72.145.44 2.ir.pool.ntp.org
  delay(3000);
  */

  String url = "195.248.243.32";
  String port = "9999";
  String payload = "{\"deviceId\":\"1212\"}";
  String query = "POST /Tracker/rest/device/exists HTTP/1.1\r\n";
  query += "Host: " + url + ":" + port + "\r\n";
  query += "Content-Type: application/json;\r\n";
  query += "Content-Length: " + String(payload.length()) + "\r\n";
  query += "\r\n";
  query += payload;
  query += "\r\n";
  
  String response = "";
  int ret_code = 0;
  ret_code = Func_Send_Command_Read_Response("AT+QIOPEN=\"TCP\",\"" + url + "\",\"" + port + "\"", &response, 300, 1000);
  
  int timer_counter = 0;
  int timeout = 10;
  bool flag_stay_in_loop = true;
  bool flag_error = false;
  do{
    timer_counter++;
    if((response.indexOf("ALREADY CONNECT") > -1) || (response.indexOf("CONNECT OK") > -1)){
        flag_stay_in_loop = false;
    } else {
        if((response.indexOf("CONNECT FAIL") > -1) || (response.indexOf("ERROR") > -1)){
          flag_stay_in_loop = false;
          flag_error = true;
        }
    }
    //Read Query Response
    ret_code = Func_Send_Command_Read_Response(NULL, &response, 300, 1000);
  }while(flag_stay_in_loop && (timer_counter < timeout));

  if((timer_counter < timeout) && (flag_error == false)){
    Serial.println("***QIOPEN was OK!");
  } else {
    Serial.println("***QIOPEN was NOT OK!");
    ret_code = Func_Send_Command_Read_Response("AT+QICLOSE", &response, 300, 1000);
    return;
  }

  
  //Set the Method to Handle Received TCP/IP Data:
  //"0": Output the received data through UART directly.
  //"1": Output a notification statement “+QIRDI: <id>,<sc>,<sid>” through UART.
  //"2": Output a notification statement “+QIRDI: <id>,<sc>,<sid>,<num>,<len>,<tlen>” through UART.  
  ret_code = Func_Send_Command_Read_Response("AT+QINDI=1", &response, 300, 1000);
  
  ret_code = Func_Send_Command_Read_Response("AT+QISEND", &response, 300, 1000);
  Serial.print(query);
  Func_Empty_Serial_Buffer();
  Serial.write(0x1A);     // ASCII code of CTRL+Z, to send message.

  String Retrieved_Response_info = "";
  timer_counter = 0;
  timeout = 10;
  flag_stay_in_loop = true;
  flag_error = false;
  do{
    timer_counter++;
    if((response.indexOf("QIRDI") > -1) && (response.indexOf("\r\n") > -1)){
        Serial.println("***QIRDI:");        
        Serial.println(response);
        response = response.substring(response.indexOf("QIRDI"));
        Retrieved_Response_info = response.substring(response.indexOf("QIRDI") + 7, response.indexOf("\r\n"));
        flag_stay_in_loop = false;
    } else {
        if((response.indexOf("SEND FAIL") > -1) || (response.indexOf("ERROR") > -1)){
          flag_stay_in_loop = false;
          flag_error = true;
        }
    }
    //Read Query Response
    ret_code = Func_Send_Command_Read_Response(NULL, &response, 300, 1000);
  }while(flag_stay_in_loop && (timer_counter < timeout));

  if((timer_counter < timeout) && (flag_error == false)){
    String command = "AT+QIRD=" + Retrieved_Response_info + ",500";
    ret_code = Func_Send_Command_Read_Response(command, &response, 300, 1000);
    
    Serial.println("***QISEND was OK!");
    Serial.println("***Response:");
    Serial.println(response);
  } else {
    Serial.println("***QISEND was NOT OK!");
    ret_code = Func_Send_Command_Read_Response("AT+QICLOSE", &response, 300, 1000);
    return;
  }

  ret_code = Func_Send_Command_Read_Response("AT+QISACK", &response, 300, 1000);
  ret_code = Func_Send_Command_Read_Response("AT+QICLOSE", &response, 300, 1000);



//  AT+QIFGCNT=0
//  AT+QICSGP=1,"CMNET"   //Set APN 
//  AT+QIREGAPP           //Optional 
//  AT+QIACT              //Optional 
//  AT+QHTTPURL=87,30     //Set URL
//  http://195.248.243.32:8888/JerseyTrackerTest/api/myresource/postlocation?lat=12&long=33
//  AT+QHTTPPOST=14,50,30 //POST the data whose size is 14 bytes and the maximum latency time for inputting is 50s.
//  lat=44&long=88
//  AT+QHTTPREAD=30       //Read the response of HTTP server
//  AT+QIDEACT            //Deactivate PDP context

//  //Send POST Request to HTTP Server (GSM_HTTP_AT_Commands_Manual.pdf):
//  String response = "";
//  int ret_code = 0;
//  ret_code = Func_Send_Command_Read_Response("AT+QIFGCNT=0", &response, 300, 1000);
//  //Set APN
//  ret_code = Func_Send_Command_Read_Response("AT+QICSGP=1,\"CMNET\"", &response, 300, 1000);
//  //Optional
//  ret_code = Func_Send_Command_Read_Response("AT+QIREGAPP", &response, 300, 1000);
//  //Optional
//  ret_code = Func_Send_Command_Read_Response("AT+QIACT", &response, 300, 1000);
//  //Set URL
//  String Message = "{\"latitude\":\"55\",\"long\":\"24\"}";
//  String url = "http://195.248.243.32:8888/Tracker/rest/device/exists";
//  ret_code = Func_Send_Command_Read_Response("AT+QHTTPURL=53,30", &response, 300, 1000);
//  Serial.print(url);  // The SMS text you want to send
//  Func_Empty_Serial_Buffer();
//  Serial.write(0x1A);     // ASCII code of CTRL+Z, to send message.
//  //POST the data whose size is 29 bytes and the maximum latency time for inputting is 50s.
//  ret_code = Func_Send_Command_Read_Response("AT+QHTTPPOST=29,50,30", &response, 300, 1000);
//  Serial.print(Message);  // The SMS text you want to send
//  Func_Empty_Serial_Buffer();
//  Serial.write(0x1A);     // ASCII code of CTRL+Z, to send message.
//  //Read the response of HTTP server
//  ret_code = Func_Send_Command_Read_Response("AT+QHTTPREAD=30", &response, 300, 1000);
//  Serial.print("response: ");
//  Serial.println(response);
//  //Deactivate PDP context
//  ret_code = Func_Send_Command_Read_Response("AT+QIDEACT", &response, 300, 1000);



}


void Func_Empty_Serial_Buffer(){
  ESP.wdtFeed();
  Serial.flush();
  delay(300);
  while(Serial.available() > 0){
    Serial.read();
  }
  ESP.wdtFeed();  
}


//At "End" of this function, "Func_Empty_Serial_Buffer()" is called.
//At "Start" of this function, if (command != null), "Func_Empty_Serial_Buffer()" is called.
int Func_Send_Command_Read_Response(String  command, 
                                    String* response,
                                    int     wait_for_response,  //time in "ms".
                                    int     response_timeout    //time in "ms".
                                    )
{
  int timer_counter = 0;
  int timeout = response_timeout/100;

  ESP.wdtFeed();
  //if( command == null ):  then( Just read the response. )
  if(command != NULL){
    Func_Empty_Serial_Buffer();
    Serial.println(command);
  }
  delay(wait_for_response);  
  ESP.wdtFeed();

  while ( (!Serial.available()) && (timer_counter <= timeout) ){
      //Do Absolutely Nothing until something is received over the serial port
      timer_counter++;
      delay(100);
      ESP.wdtFeed();
  }
  
  if(timer_counter > timeout) {
      Func_Empty_Serial_Buffer();
      return No_Response_From_MC60;  
  } else {
      String str = "";
      while(Serial.available() > 0){
        str += Serial.readString();
      }
      
      if(str.indexOf("OK") > -1){
        (*response) = str;
        Func_Empty_Serial_Buffer();
        return OK_From_MC60;
      } else {
        (*response) = str;
        Func_Empty_Serial_Buffer();
        return Error_From_MC60;
      }
  }
}


int Func_Send_SMS(String Phone_Number, String Message){
  String  response = "";
  int     ret_code = 0;
  int     timer_counter;
  int     timeout;

  timeout = 10;
  timer_counter = 0;
  do{
    timer_counter++;
    ret_code = OK_From_MC60;

    //Sets the GSM Module in 0:PDU Mode/1:Text Mode
    ret_code += Func_Send_Command_Read_Response("AT+CMGF=1", &response, 300, 1000);
    
    ret_code += Func_Send_Command_Read_Response("AT+CSMP=17,167,0,0", &response, 300, 1000);
    
    //Set Character set as GSM/IRA/PCCP437/... which is used by the TE
    ret_code += Func_Send_Command_Read_Response("AT+CSCS=\"GSM\"", &response, 300, 1000);
  } while(ret_code != OK_From_MC60 && timer_counter <= timeout);
  if(ret_code != OK_From_MC60){
    return ret_code;
  }
  
  timeout = 3;
  timer_counter = 0;
  do{
    timer_counter++;
    ret_code = OK_From_MC60;

    // Mobile Number
    //"AT+CMGS=\"09163005228\""
    String phone_number_command = "AT+CMGS=\"" + Phone_Number + "\""; 
    Func_Send_Command_Read_Response(phone_number_command, &response, 300, 1000);

    Serial.print(Message);  // The SMS text you want to send
    Func_Empty_Serial_Buffer();

    Serial.write(0x1A);     // ASCII code of CTRL+Z, to send message.
    ret_code += Func_Send_Command_Read_Response(NULL, &response, 300, 6000);
  } while(ret_code != OK_From_MC60 && timer_counter <= timeout);
  if(ret_code != OK_From_MC60){
    return ret_code;
  }
  
  return OK_From_MC60;
}


void setup() {
  Serial.begin(115200);
  delay(500);

  ESP.wdtDisable();
  ESP.wdtEnable(WDTO_8S);
  
  Func_Empty_Serial_Buffer();
  Serial.println();
  Serial.println("Booting Sketch...");
  Func_Empty_Serial_Buffer();
  
  pinMode(PIN_ESP_LED, OUTPUT);
  pinMode(PIN_PWRKEY, OUTPUT);

  //Turn ON MC60:
  String response = "";
  int ret_code = 0;
  ret_code = Func_Send_Command_Read_Response("AT", &response, 300, 1000);
  while(ret_code != OK_From_MC60){
    digitalWrite(PIN_PWRKEY, HIGH);
    delay(3000);
    digitalWrite(PIN_PWRKEY, LOW);  
    delay(1000);
    Serial.println("MC60 didn't answer command AT");
    Func_Empty_Serial_Buffer();
    ret_code = Func_Send_Command_Read_Response("AT", &response, 300, 1000);
  }

  ret_code = Func_Send_Command_Read_Response("AT+QGNSSC=0", &response, 300, 1000);
  delay(1000);
   
  //Turn OFF echo:
  ret_code = Func_Send_Command_Read_Response("ATE0", &response, 300, 1000);
  if(ret_code != OK_From_MC60){
    ESP.restart();
  }
  
  //Enable SMS Indications:
  //Sets the GSM Module in 0:PDU Mode/1:Text Mode
  ret_code = Func_Send_Command_Read_Response("AT+CMGF=1", &response, 300, 1000);
  //Set character set as GSM which is used by the TE
  ret_code = Func_Send_Command_Read_Response("AT+CSCS=\"GSM\"", &response, 300, 1000);
  //Set SMS-DELIVERs are routed directly to the TE
  ret_code = Func_Send_Command_Read_Response("AT+CNMI=2,2", &response, 300, 1000);
  
  Func_Send_SMS("09163005228", "Device Started Working!");
  Func_Empty_Serial_Buffer();

  //prekey(128);
  Send_TCP();
  Send_TCP();
  Send_TCP();

  byte Key [] = {1,2,3,4, 1,2,3,4, 1,2,3,4, 1,2,3,4};
//  String Plaintext = "1234567887654321";
//  byte Ciphertext [16] = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0};
//  AES_Encrypt_ECB_stringInput(Plaintext, Ciphertext, Key);
//  Serial.print("plaintext (String): ");
//  Serial.println(Plaintext);
//  Serial.print("ciphertext (Hex):   ");
//  Serial.println(byteArraytoHexStr(Ciphertext, 16));

  //AES_CBC Encryption:
  String Plaintext = "123456781234567887654321876543211234123412341234";
  int number_of_Blocks = Plaintext.length()/16;
  unsigned char Plaintext_charArray [16*number_of_Blocks+1];
  byte Ciphertext_2 [16*number_of_Blocks];
  Plaintext.toCharArray((char*)Plaintext_charArray, 16*number_of_Blocks+1);
  AES_Encrypt_CBC(Plaintext_charArray, Ciphertext_2, Key, number_of_Blocks);
  
  Serial.println(" ");
  Serial.println("=================================================================");
  for(int i=0; i<number_of_Blocks; i++){
    Serial.print("plaintext Block "); 
    Serial.print(i+1);
    Serial.print(" (String):    ");
    Serial.println(byteArraytoHexStr(Plaintext_charArray+(16*i), 16));
  }
  Serial.println("-----------------------------------------------------------------");  
  for(int i=0; i<number_of_Blocks; i++){
    Serial.print("ciphertext Block "); 
    Serial.print(i+1);
    Serial.print(" (Hex):      ");
    Serial.println(byteArraytoHexStr(Ciphertext_2+(16*i), 16));
  }
  Serial.println("=================================================================");
  
}


String byteArraytoHexStr(unsigned char *data, int len)
{
  char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
                   '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'};
  String s = "";
  for (int i = 0; i < len; i++) {
    s += hexmap[(data[i] & 0xF0) >> 4];
    s += hexmap[(data[i] & 0x0F)];
  }
  return s;
}

bool    flag_Get_SMS    = 1;
int     ADC_value;
String  serial_response = "Initial value!";
int     return_code     = 5;

 
//"WiFi" and "TCP/IP" tasks get a chance to handle any pending events
//each time the "loop() function completes", OR when "delay() is called".
//--> So DON'T have loops more than ">50ms" without calling "delay()"!
void loop() {
  ESP.wdtFeed();
//  httpServer.handleClient();
  ESP.wdtFeed();
  
  digitalWrite(PIN_ESP_LED, LOW);   // Turn ON LED
  delay(100);
  digitalWrite(PIN_ESP_LED, HIGH);  // Turn OFF LED
  delay(100);
  ESP.wdtFeed();

  // Read VCC Voltage:
  ADC_value = ESP.getVcc();
  float ADC_value_float = (float)ADC_value/1024.0f;
  //Serial.printf("ADC_value = %d   VCC = %f\n", ADC_value, ADC_value_float);
  //Func_Empty_Serial_Buffer();

  if(flag_Get_SMS){
    String Rec_SMS = "";
    String Phone_num = "";
    String Message = "";
        
    while(Serial.available() > 0){
      Rec_SMS += Serial.readString();
    }
    if((Rec_SMS.indexOf("CMT") > -1) && 
       (Rec_SMS.indexOf("\n")  > -1)){
      Phone_num = Rec_SMS.substring(Rec_SMS.indexOf("CMT") + 6, Rec_SMS.indexOf("CMT") + 6 + 13);
      Rec_SMS   = Rec_SMS.substring(Rec_SMS.indexOf("CMT") + 6 + 14);
      Message   = Rec_SMS.substring(Rec_SMS.indexOf("\n")  + 1);;      

      //Power on GNSS
      return_code = Func_Send_Command_Read_Response("AT+QGNSSC=1", &serial_response, 300, 1000);
      //
      return_code = Func_Send_Command_Read_Response("AT+QIFGCNT=2", &serial_response, 300, 1000);
      //
      return_code = Func_Send_Command_Read_Response("AT+QICSGP=1,\"CMNET\"", &serial_response, 300, 1000);
      //Read time synchronization status
      return_code = Func_Send_Command_Read_Response("AT+QGNSSTS?", &serial_response, 300, 1000);
      //Check network status
      return_code = Func_Send_Command_Read_Response("AT+CREG?;+CGREG?", &serial_response, 300, 1000);
      //Set reference location information for QuecFastFix Online
      return_code = Func_Send_Command_Read_Response("AT+QGREFLOC=35.7265,51.3509", &serial_response, 300, 1000);
      //Enable EPOTM function
      return_code = Func_Send_Command_Read_Response("AT+QGNSSEPO=1", &serial_response, 300, 1000);
      //Trigger EPOTM function
      return_code = Func_Send_Command_Read_Response("AT+QGEPOAID", &serial_response, 300, 1000);
      //Read GNSS
      return_code = Func_Send_Command_Read_Response("AT+QGNSSRD=\"NMEA/GGA\"", &serial_response, 300, 1000);
      String Location = "";
      if((serial_response.indexOf("GNGGA") > -1) && 
         (serial_response.indexOf(",N,")   > -1) &&
         (serial_response.indexOf(",E,")   > -1)){
            String Latitude       = serial_response.substring(serial_response.indexOf(",N,") -  9, serial_response.indexOf(",N,") - 9  + 4);
            Latitude = Latitude   + serial_response.substring(serial_response.indexOf(",N,") -  4, serial_response.indexOf(",N,") - 4  + 3); 
            String Longitude      = serial_response.substring(serial_response.indexOf(",E,") - 10, serial_response.indexOf(",E,") - 10 + 5);
            Longitude = Longitude + serial_response.substring(serial_response.indexOf(",E,") -  4, serial_response.indexOf(",E,") -  4 + 2);
            Location = "OK" + Latitude + Longitude;           
            Serial.println(Location);
            if(Location.length() != 16) {
              Location = "Length of Location was NOT 16!";              
            } else {
              AES aes;
              int bits = 128;
              byte key[] = {0x54,0x88,0x59,0,0,0,0,0,0,0,0,0,0,0,0,0};
              unsigned long long int my_iv = 0;
              byte plain[17];
              Location.getBytes(plain, 17);
              int plainLength = sizeof(plain)-1;  // don't count the trailing /0 of the string !
              int padedLength = plainLength + N_BLOCK - plainLength % N_BLOCK;
              aes.iv_inc();
              byte iv [N_BLOCK] ;
              byte cipher [padedLength] ;
              aes.set_IV(my_iv);
              aes.get_IV(iv);
              aes.do_aes_encrypt(plain, plainLength, cipher, key, bits, iv);
              Serial.print("plaintext = ");
              aes.printArray(plain,16);
              Serial.print("\nciphertext = ");
              aes.printArray(cipher,16);
              Serial.println("");

              Location = "";
              Location = byteArraytoHexStr(cipher, 16);
//              for(int i=0; i<16; i++){
//                Location += *(char*)(cipher+i);
//                Serial.println();
//              }

            }
      } else {
            Location = "ERROR: No Location!";      
      }

      Serial.print("\nLocation = ");
      Serial.println(Location);
      return_code = Func_Send_SMS(Phone_num, Location);
    }
  }
   
}
