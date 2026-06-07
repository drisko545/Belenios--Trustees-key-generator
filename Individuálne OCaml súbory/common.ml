(**************************************************************************)
(*                                BELENIOS                                *)
(*                                                                        *)
(*  Copyright © 2024-2024 Inria                                           *)
(*                                                                        *)
(*  This program is free software: you can redistribute it and/or modify  *)
(*  it under the terms of the GNU Affero General Public License as        *)
(*  published by the Free Software Foundation, either version 3 of the    *)
(*  License, or (at your option) any later version, with the additional   *)
(*  exemption that compiling, linking, and/or using OpenSSL is allowed.   *)
(*                                                                        *)
(*  This program is distributed in the hope that it will be useful, but   *)
(*  WITHOUT ANY WARRANTY; without even the implied warranty of            *)
(*  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU     *)
(*  Affero General Public License for more details.                       *)
(*                                                                        *)
(*  You should have received a copy of the GNU Affero General Public      *)
(*  License along with this program.  If not, see                         *)
(*  <http://www.gnu.org/licenses/>.                                       *)
(**************************************************************************)

open Js_of_ocaml
open Js_of_ocaml_tyxml
open Belenios
open Belenios_js.Common

let wrap_handler handler x =
  (* Handler spustame asynchronne, aby UI nezamrzlo pri spracovani suboru. *)
  let@ () = Lwt.async in
  Lwt.catch
    (fun () -> handler x)
    (fun _ ->
      (* Pri chybe zobrazime pouzivatelovi jasnu informaciu, ze pravdepodobne
        nahral nespravny subor. *)
      let open (val !Belenios_js.I18n.gettext) in
      alert
      @@ s_
           "Error while processing the private key. Did you load the right \
            file?";
      Lwt.return_unit)

let make_private_key_input handler =
  let open (val !Belenios_js.I18n.gettext) in
  let open Tyxml_js.Html in
  (* Skryte pole uchova nami nacitany privatny kluc pre dalsi krok. *)
  let raw_elt = input ~a:[ a_id "private_key"; a_input_type `Hidden ] () in
  let raw_dom = Tyxml_js.To_dom.of_input raw_elt in
  let onchange _ =
    (* Ked sa zmeni hodnota skryteho pola, posleme obsah do nadriadeneho handlera. *)
    wrap_handler handler (Js.to_string raw_dom##.value);
    Js._false
  in
  raw_dom##.onchange := Dom_html.handler onchange;
  (* Vstup pre subor nacita vybrany kluc lokalne a odosle jeho obsah do handlera. *)
  let file_elt = input ~a:[ a_id "private_key_file"; a_input_type `File ] () in
  let file_dom = Tyxml_js.To_dom.of_input file_elt in
  let onchange _ =
    (* Najprv bezpecne ziskame zoznam suborov z inputu. *)
    let ( let& ) x f = Js.Opt.case x (fun () -> Js._false) f in
    let ( let$ ) x f = Js.Optdef.case x (fun () -> Js._false) f in
    (* Vyberieme prvy subor, pretoze v tomto rozhrani ocakavame jeden kluc. *)
    let$ files = file_dom##.files in
    let& file = files##item 0 in
    (* Obsah suboru nacitame cez FileReader, aby sa neodovzdaval priamo cez DOM. *)
    let reader = new%js File.fileReader in
    reader##.onload :=
      Dom.handler (fun _ ->
          (* Po nacitani preposleme textovy obsah dalej do spracovania. *)
          let& content = File.CoerceTo.string reader##.result in
          wrap_handler handler (Js.to_string content);
          Js._false);
    reader##readAsText file;
    Js._false
  in
  file_dom##.onchange := Dom_html.handler onchange;
  div
    ~a:[ a_id "input_private_key" ]
    [
      txt @@ s_ "Please load your private key from a file:";
      txt " ";
      file_elt;
      raw_elt;
    ]
