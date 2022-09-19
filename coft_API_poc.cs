
using System;
using Jose;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace ctc.coft.api.poc
{
    class Program
    {

        private static readonly string SIGNATURE_FORMAT = "{0}\n{1}\n{2}\n{3}\n{4}\n{5}\n{6}\n";
        private static readonly string AUTH_HEADER_FORMAT = "MAC id=\"{0}\",ts=\"{1}\",nonce=\"{2}\",bodyhash=\"{3}\",mac=\"{4}\"";

        public static string CreateTimestamp()
        {
            return DateTimeOffset.UtcNow.ToUnixTimeMilliseconds().ToString();
        }

        public static string generateHash(string secretKey, string payload){
              //create crypto using client secret
            var hmac = new System.Security.Cryptography.HMACSHA256(Encoding.UTF8.GetBytes(secretKey));
            hmac.Initialize();

            //body hash generation
            byte[] rawPayloadHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(payload));
            
            //Return message hash
            return Convert.ToBase64String(rawPayloadHash);
        }

        public static string generateHMAC(string clientSecret, string resourcePath, string host, int port, 
                                          string httpMethod, string payload, string nonce, string ts, string bodyHash){
            //create hash 
            string signature = string.Format(SIGNATURE_FORMAT, ts, nonce, httpMethod, resourcePath, host, port, bodyHash);
            return generateHash(clientSecret, signature);
        }


        public static string buildHttpAuthenticationHeader(String clientID, string ts, string nonce, string bodyHash, string hmac){
            return string.Format(AUTH_HEADER_FORMAT, clientID, ts, nonce, bodyHash, hmac);
        }

        public static string encryptWithAES128GCM256KW(String keyID, String encryptionKey, String data){
           
            var extraHeaders = new Dictionary<string, object>();
            extraHeaders.Add("kid", keyID);
            
            String cipherText = Jose.JWT.Encode(data, Convert.FromBase64String(encryptionKey), 
                                                JweAlgorithm.A256KW, JweEncryption.A128GCM, extraHeaders:extraHeaders);
            return cipherText;
        }

        public static string decryptWithAES128GCM256KW(String encryptionKey, String data){
            
            String recoveredText = Jose.JWT.Decode(data, Convert.FromBase64String(encryptionKey), 
                                                JweAlgorithm.A256KW, JweEncryption.A128GCM);

            return recoveredText;
        }
        
        //Stub data to simulate token provisioning request
        public static string buildTokenProvisioningRequest(String encryption_key_id, 
                                                           String encryption_key,
                                                           String card_no,
                                                           int card_exp_month,
                                                           int card_exp_year,
                                                           String authentication_value){

            //payload = [AccountData, RiskAssessmentData, UserData]
            Dictionary<Object, Object> payload = new Dictionary<object, object>();

            //Add Risk Assessment Data to payload
            Dictionary<Object, Object> RiskAssessmentData = new Dictionary<object, object>
            {
                {"account_input_method", "User Input"},
                {"pan_tenure_on_file", "8"},
                {"ip_address", "127.0.0.1"}
            };
            payload.Add("risk_assessment_data", RiskAssessmentData);

            //Add User Data to payload
            Dictionary<Object, Object> UserData = new Dictionary<object, object>
            {
                {"user_id", "3307070056"},
                {"email", "John.Doe@xfactor.com"},
                {"phone", "+91111111111"},
                {"name", "John Doe"}
            };
            payload.Add("user_data", UserData);


             //AccountData = [account_type, credit_card, billing_address, authentication_method]
            Dictionary<Object, Object> AccountData = new Dictionary<object, object>
            {
                {"account_type", "credit_card"},
                {"credit_card", new Dictionary<object, object>
                    {
                        {"account_number", card_no},
                        {"expiry_month", card_exp_month},
                        {"expiry_year", card_exp_year}
                    } 
                },
                {"billing_address", new Dictionary<object, object>
                    {
                        {"address_line1", "Blk 808 Good View Park"},
                        {"address_line2", "Somewhere St."},
                        {"address_line3", "#08-808"},
                        {"city", "New Delhi"},
                        {"country", "IN"}
                    }                    
                },
                {"authentication_method", new Dictionary<object, object>
                    {
                        {"method", "AEVV"},
                        {"value", authentication_value}
                    }
                }
            };          

            //Serialize 'Account Data' into JSON string 
            string jsonAccountData = JsonSerializer.Serialize(AccountData);
            
            //Encrypt  'Account Data' JSON with AES A128GCM with A56KW 
            string encAccountData = encryptWithAES128GCM256KW(encryption_key_id,  encryption_key, jsonAccountData);
            
            //Add encrypted account data to payload
            payload.Add("account_data", encAccountData);

            //return JSON serialized payload
            return JsonSerializer.Serialize(payload);;
                        
        }

		//Stub data to simulate 'purchase token' API  request
        public static string buildPurchaseTokenRequest(String encryption_key_id, 
                                                           String encryption_key,
                                                           String token_ref_id,
                                                           String merchant_id,
                                                           int amount)
        {

            //payload = [token_ref_id, RiskAssessmentData, transaction_data, UserData]
            Dictionary<Object, Object> payload = new Dictionary<object, object>();

            //Token Reference ID
            payload.Add("token_ref_id", token_ref_id);

            //Add Risk Assessment Data to payload
            Dictionary<Object, Object> RiskAssessmentData = new Dictionary<object, object>
            {
                {"account_input_method", "User Input"},
                {"pan_tenure_on_file", "8"},
                {"ip_address", "127.0.0.1"}
            };
            payload.Add("risk_assessment_data", RiskAssessmentData);

            //Add User Data to payload
            Dictionary<Object, Object> UserData = new Dictionary<object, object>
            {
                {"user_id", "3307070056"},
                {"email", "John.Doe@xfactor.com"},
                {"phone", "+91111111111"},
                {"name", "John Doe"}
            };
            payload.Add("user_data", UserData);


             //AccountData = [account_type, credit_card, billing_address, authentication_method]
            Dictionary<Object, Object> TransactionData = new Dictionary<object, object>
            {
                {"transaction_data", new Dictionary<object, object>
                    {
                        {"account_type", "credit_card"},
                        {"amount", amount},
                        {"merchant_id", merchant_id},
                        {"payment_credential_type", "DCSC"}
                    }
                }
            };          


            //Serialize 'TransactionData' into JSON string 
            string jsonTransactionData = JsonSerializer.Serialize(TransactionData);
            
            //Encrypt  'TransactionData' JSON with AES A128GCM with A56KW 
            string encTransactionData = encryptWithAES128GCM256KW(encryption_key_id,  encryption_key, jsonTransactionData);
            
            //Add encrypted account data to payload
            payload.Add("encrypted_payload", encTransactionData);

            //return JSON serialized payload
            return JsonSerializer.Serialize(payload);;
                        
        }

        //Commnon HTTP Client service
          public static string httpClientService( String token_requestor_id,
                                                 String client_id,
                                                 String client_secret,                                             
                                                 String host,
                                                 String api_resource_path,
                                                 int port,
                                                 String http_method,
                                                 String payload)
         {   
            
            //Test Sandbox URL for Token Provisioning API
            String url = "https://" + host + api_resource_path;
            Console.WriteLine("Request URL: " + url);

            //Generate nonce
            String nonce = Guid.NewGuid().ToString();
            
            //Generate timestamp
            String ts = CreateTimestamp();  
                        
           //Generate Body Hash
		   String bodyHash = generateHash( client_secret, payload );

           //compute HMAC
           String hmac = generateHMAC( client_secret, 
                        api_resource_path, //resource path
                        host, //host
                        port, //port
                        http_method,  //http method
                        payload,
                        nonce,
                        ts,
                        bodyHash);

            //build http Authentication header
            String authHeader = buildHttpAuthenticationHeader(client_id, ts, nonce, bodyHash, hmac);
 
            Console.WriteLine("HTTP Authentication header: " + authHeader); 
            Console.WriteLine("Request: " + payload);   

            String apiResponse = "";
            var task = Task.Factory.StartNew ( () => {

                 using (var client = new HttpClient())
                {
                    //Add HTTP headers
                    client.DefaultRequestHeaders.Add("Accept-Language", "en-US");                 
                    client.DefaultRequestHeaders.Add("Authorization", authHeader);
                    client.DefaultRequestHeaders.Add("x-amex-api-key", client_id); // client_id
                    client.DefaultRequestHeaders.Add("x-amex-token-requester-id", token_requestor_id); // TRID
                    client.DefaultRequestHeaders.Add("x-amex-request-id", Convert.ToBase64String(Guid.NewGuid().ToByteArray()));

                    //POST API request                   
                    HttpResponseMessage response = client.PostAsync(url, new StringContent(payload, Encoding.UTF8, "application/json")).Result;            
                    apiResponse = response.Content.ReadAsStringAsync().Result;
                }
                
            });
                      	
           task.Wait();          
           Console.WriteLine(); 
           Console.WriteLine("Response: " + apiResponse);

           return apiResponse;
         }


        //Simulate Token Provisioning Request
        public static string simulateTokenProvisioning( String token_requestor_id,
                                                 String client_id,
                                                 String client_secret,
                                                 String encryption_key_id,
                                                 String encryption_key,
                                                 String card_no,
                                                 int card_exp_month,
                                                 int card_exp_year,
                                                 String authentication_value,
                                                 String host,
                                                 String api_resource_path,
                                                 int port,
                                                 String http_method)
         {   
                                      
            //build JSON payload
            string payload = buildTokenProvisioningRequest(encryption_key_id,
                                                           encryption_key, 
                                                           card_no, 
                                                           card_exp_month, 
                                                           card_exp_year,
                                                           authentication_value);
            //http call            
            String apiResponse = httpClientService(token_requestor_id,
                                                   client_id, 
                                                   client_secret, 
                                                   host, 
                                                   api_resource_path, 
                                                   port, 
                                                   http_method, 
                                                   payload);
            
            //Process API response
            string token_ref_id;
            string secure_token_data;
            String recovered_token_data;

            using (JsonDocument doc = JsonDocument.Parse(apiResponse))
            {
                JsonElement root = doc.RootElement;

                //Get Token Ref ID
                token_ref_id = root.GetProperty("token_ref_id").ToString();
                //Console.WriteLine("token_ref_id: " + token_ref_id);

                //Get secure token block
                secure_token_data =  root.GetProperty("secure_token_data").ToString();              
                
                //Drecrypt secure token data
                recovered_token_data = decryptWithAES128GCM256KW(encryption_key, secure_token_data);
                Console.WriteLine("recovered_token_data: " + recovered_token_data);
            }

            return token_ref_id;            
        }

       
        public static void simulatePurchaseTokenRequest( String token_requestor_id,
                                                 String client_id,
                                                 String client_secret,
                                                 String encryption_key_id,
                                                 String encryption_key,
                                                 String token_ref_id,
                                                 String merchant_id, 
                                                 int amount,
                                                 String host,
                                                 String api_resource_path,
                                                 int port,
                                                 String http_method)
         {               
            //build JSON payload
            string payload = buildPurchaseTokenRequest(encryption_key_id,
                                                           encryption_key, 
                                                           token_ref_id, 
                                                           merchant_id, 
                                                           amount);
            //http call            
            String apiResponse = httpClientService(token_requestor_id,
                                                   client_id, 
                                                   client_secret, 
                                                   host, 
                                                   api_resource_path, 
                                                   port, 
                                                   http_method, 
                                                   payload);
            //Process API response
            string encrypted_payload;
            String recovered_payment_credential;

            using (JsonDocument doc = JsonDocument.Parse(apiResponse))
            {
                JsonElement root = doc.RootElement;

                //Get secure token block
                encrypted_payload =  root.GetProperty("encrypted_payload").ToString();              
                
                //Drecrypt encrypted_payload
                recovered_payment_credential = decryptWithAES128GCM256KW(encryption_key, encrypted_payload);
                Console.WriteLine("recovered_payment_credential: " + recovered_payment_credential);
            }            
                        
        }

        
        static void Main(string[] args)
        {            
            //Credentials from Amex for Developers sire 'Amex Token Service'
            String token_requestor_id = "<Token Requestor ID value here>";
            String client_id = "<Client ID value here>";
            String client_secret = "<Client Sevret value here>";
            String encryption_key_id =  "<Encryption Key ID value here>";
            String encryption_key = "<Encryption Key value here>";
            String sandbox_host = "api.qa.americanexpress.com";
            String sandbox_provisioning_resource_path = "/payments/digital/v2/tokens/provisionings";
            String sandbox_purchase_token_resource_path = "/payments/digital/v2/tokens/purchasetokens";
            String amex_se_no = "<Amex SE10 here>";

            //Simulate Sandbox Test case #1, see 'Test Card Numbers and Scenarios' section
            // @ https://developer.americanexpress.com/products/amex-token-service/guide#details
            //
            //Test Case #1 Card Info [card_no=371111xxxxx1114, month=12, year=2030]
            //Test Case #3 Card Info [card_no=371111xxxxx1161, month=11, year=2030]
            string card_no = "<Test Card No here>";

            //Test Authentication value [BwACAkYlhgICEwADMTE2EAAAAAA=]
            string authentication_value =  "BwACAkYlhgICEwADMTE2EAAAAAA=";
            
            Console.WriteLine("Simulate Token Provisioning Request...");
            string token_ref_id = simulateTokenProvisioning(token_requestor_id,
                                                            client_id, 
                                                            client_secret, 
                                                            encryption_key_id, 
                                                            encryption_key,
                                                            card_no,
                                                            12, //test card exp month
                                                            2030, //test card exp year
                                                            authentication_value,
                                                            sandbox_host,
                                                            sandbox_provisioning_resource_path,
                                                            443,
                                                            "POST");


            //'TokenRefID' can then be used for requesting payment credential with PurchaseToken API.
            Console.WriteLine("token_ref_id: " + token_ref_id);

            Console.WriteLine();
            Console.WriteLine("Simulate Payment Credential Request...");
            //Request for Payment Credential
            simulatePurchaseTokenRequest(token_requestor_id, 
                                         client_id, 
                                         client_secret, 
                                         encryption_key_id, 
                                         encryption_key,
                                         token_ref_id,  //obtained from 'token provisioning' API call
                                         amex_se_no, 
                                         150, //test purchase amount i.e. INR 1.50
                                         sandbox_host,
                                         sandbox_purchase_token_resource_path, 
                                         443,
                                         "POST");
        }         
    }
}
