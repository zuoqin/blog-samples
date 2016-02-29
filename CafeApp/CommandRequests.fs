module CommandRequests
open System
open Domain
open Commands
open FSharp.Data

[<Literal>]
let OpenTabJson = """{
  "openTab" : {
    "tableNumber" : 1
  }
}"""
type OpenTabReq = JsonProvider<OpenTabJson>

let (|OpenTabRequest|_|) payload =
  try
    let req = OpenTabReq.Parse(payload).OpenTab
    { Id = Guid.NewGuid(); TableNumber = req.TableNumber}
    |> Some
  with
  | ex -> None

[<Literal>]
let PlaceOrderJson = """{
  "placeOrder" : {
    "tabId" : "2a964d85-f503-40a1-8014-2c8ee5ac4a49",
    "foodMenuNumbers" : [8,9],
    "drinkMenuNumbers" : [10,11]
  }
}"""
type PlaceOrderReq = JsonProvider<PlaceOrderJson>

let (|PlaceOrderRequest|_|) payload =
  try
    let req = PlaceOrderReq.Parse(payload).PlaceOrder
    (req.TabId, req.DrinkMenuNumbers, req.FoodMenuNumbers) |> Some
  with
  | ex -> None

[<Literal>]
let ServeDrinksJson = """{
    "serveDrinks" : {
      "tabId" : "2a964d85-f503-40a1-8014-2c8ee5ac4a49",
      "menuNumber" : 10
    }
}"""
type ServeDrinksReq = JsonProvider<ServeDrinksJson>

let (|ServeDrinksRequest|_|) payload =
  try
    let req = ServeDrinksReq.Parse(payload).ServeDrinks
    (req.TabId, req.MenuNumber) |> Some
  with
  | ex -> None