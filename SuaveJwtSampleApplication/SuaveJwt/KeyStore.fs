module KeyStore

open Microsoft.IdentityModel.Tokens
open Encodings


let securityKey sharedKey : Microsoft.IdentityModel.Tokens.SecurityKey =
    let symmetricKey = sharedKey |> Base64String.decode
    new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(symmetricKey) :> SecurityKey

let hmacSha256 secretKey =
    new SigningCredentials(secretKey,SecurityAlgorithms.HmacSha256Signature)
