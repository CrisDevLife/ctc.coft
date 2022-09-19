# ctc.coft

This is a simple POC client program implementing '/provisionings' and '/purchasetokens' APIs as defined in 'https://developer.americanexpress.com/products/amex-token-service/'.

This sample program is provided as-is, and its sole purpose is to demonstrate how to handle the API calls to abovementioned Amex token services and should therefore NOT be used in production environment.

Also, this sample code was created out of personal hobby, and is by no means endorsed by the American Express company. 


NB: Below inputs are required prior to compiling the code.

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
  string card_no = "<Test Card No here>";
  

Lastly, the following C# packages were referenced for these sample program:
    <PackageReference Include="jose-jwt" Version="4.0.1" />
    <PackageReference Include="System.Text.Json" Version="6.0.5" />
