package security

type UN struct {
	Id     string
	Alpha2 string
	Alpha3 string
	Name   string
}

type AU struct {
	Id   string
	Name string
	UNId string
}

type Country struct {
	UN UN
	AU AU
}

func CountryUNAlpha2toAustralianId(unAlpha2 string) string {
	unAlpha2 = strings.ToUpper(unAlpha2)
	for _, c := range countries {
		if c.UN.Alpha2 == unAlpha2 {
			return c.AU.Id
		}
	}
	return ""
}

func IsCountryName(country string) bool {
	for _, c := range countries {
		if c.UN.Name == country {
			return true
		}
		if c.AU.Name == country {
			return true
		}
	}
	return false
}

func CountryByName(country string) *Country {
	for i, c := range countries {
		if c.UN.Name == country {
			return &countries[i]
		}
		if c.AU.Name == country {
			return &countries[i]
		}
	}
	return nil
}

// CountryByCode looks up a country by code. Code may be the UN three digit
// number, UN two or three character string, or Australian four digit id.
func CountryByCode(country string) *Country {
	for i, c := range countries {
		if c.UN.Alpha2 == country {
			return &countries[i]
		}
		if c.UN.Alpha3 == country {
			return &countries[i]
		}
		if c.UN.Id == country {
			return &countries[i]
		}
		if c.AU.Id == country {
			return &countries[i]
		}
	}
	return nil
}

var countries = []Country{
	Country{UN: UN{"004", "Afghanistan", "AF", "AFG"}, AU: AU{"7201", "Afghanistan", "004"}},
	Country{UN: UN{"248", "Åland Islands", "AX", "ALA"}, AU: AU{"2408", "Aland Islands", "248"}},
	Country{UN: UN{"008", "Albania", "AL", "ALB"}, AU: AU{"3201", "Albania", "008"}},
	Country{UN: UN{"012", "Algeria", "DZ", "DZA"}, AU: AU{"4101", "Algeria", "012"}},
	Country{UN: UN{"016", "American Samoa", "AS", "ASM"}, AU: AU{"1506", "Samoa, American", "016"}},
	Country{UN: UN{"020", "Andorra", "AD", "AND"}, AU: AU{"3101", "Andorra", "020"}},
	Country{UN: UN{"024", "Angola", "AO", "AGO"}, AU: AU{"9201", "Angola", "024"}},
	Country{UN: UN{"660", "Anguilla", "AI", "AIA"}, AU: AU{"8401", "Anguilla", "660"}},
	Country{UN: UN{"010", "Antarctica", "AQ", "ATA"}, AU: AU{"", "", ""}},
	Country{UN: UN{"028", "Antigua and Barbuda", "AG", "ATG"}, AU: AU{"8402", "Antigua and Barbuda", "028"}},
	Country{UN: UN{"032", "Argentina", "AR", "ARG"}, AU: AU{"8201", "Argentina", "032"}},
	Country{UN: UN{"051", "Armenia", "AM", "ARM"}, AU: AU{"7202", "Armenia", "051"}},
	Country{UN: UN{"533", "Aruba", "AW", "ABW"}, AU: AU{"8403", "Aruba", "533"}},
	Country{UN: UN{"036", "Australia", "AU", "AUS"}, AU: AU{"1199", "Australian External Territories, nec", "036"}},
	Country{UN: UN{"040", "Austria", "AT", "AUT"}, AU: AU{"2301", "Austria", "040"}},
	Country{UN: UN{"031", "Azerbaijan", "AZ", "AZE"}, AU: AU{"7203", "Azerbaijan", "031"}},
	Country{UN: UN{"044", "Bahamas", "BS", "BHS"}, AU: AU{"8404", "Bahamas", "044"}},
	Country{UN: UN{"048", "Bahrain", "BH", "BHR"}, AU: AU{"4201", "Bahrain", "048"}},
	Country{UN: UN{"050", "Bangladesh", "BD", "BGD"}, AU: AU{"7101", "Bangladesh", "050"}},
	Country{UN: UN{"052", "Barbados", "BB", "BRB"}, AU: AU{"8405", "Barbados", "052"}},
	Country{UN: UN{"112", "Belarus", "BY", "BLR"}, AU: AU{"3301", "Belarus", "112"}},
	Country{UN: UN{"056", "Belgium", "BE", "BEL"}, AU: AU{"2302", "Belgium", "056"}},
	Country{UN: UN{"084", "Belize", "BZ", "BLZ"}, AU: AU{"8301", "Belize", "084"}},
	Country{UN: UN{"204", "Benin", "BJ", "BEN"}, AU: AU{"9101", "Benin", "204"}},
	Country{UN: UN{"060", "Bermuda", "BM", "BMU"}, AU: AU{"8101", "Bermuda", "060"}},
	Country{UN: UN{"064", "Bhutan", "BT", "BTN"}, AU: AU{"7102", "Bhutan", "064"}},
	Country{UN: UN{"068", "Bolivia (Plurinational State of)", "BO", "BOL"}, AU: AU{"8202", "Bolivia", "068"}},
	Country{UN: UN{"535", "Bonaire, Sint Eustatius and Saba", "BQ", "BES"}, AU: AU{"8433", "Bonaire, Sint Eustatius and Saba", "535"}},
	Country{UN: UN{"070", "Bosnia and Herzegovina", "BA", "BIH"}, AU: AU{"3202", "Bosnia and Herzegovina", "070"}},
	Country{UN: UN{"072", "Botswana", "BW", "BWA"}, AU: AU{"9202", "Botswana", "072"}},
	Country{UN: UN{"074", "Bouvet Island", "BV", "BVT"}, AU: AU{"", "", ""}},
	Country{UN: UN{"076", "Brazil", "BR", "BRA"}, AU: AU{"8203", "Brazil", "076"}},
	Country{UN: UN{"086", "British Indian Ocean Territory", "IO", "IOT"}, AU: AU{"", "", ""}},
	Country{UN: UN{"096", "Brunei Darussalam", "BN", "BRN"}, AU: AU{"5201", "Brunei Darussalam", "096"}},
	Country{UN: UN{"100", "Bulgaria", "BG", "BGR"}, AU: AU{"3203", "Bulgaria", "100"}},
	Country{UN: UN{"854", "Burkina Faso", "BF", "BFA"}, AU: AU{"9102", "Burkina Faso", "854"}},
	Country{UN: UN{"108", "Burundi", "BI", "BDI"}, AU: AU{"9203", "Burundi", "108"}},
	Country{UN: UN{"132", "Cabo Verde", "CV", "CPV"}, AU: AU{"9104", "Cabo Verde", "132"}},
	Country{UN: UN{"116", "Cambodia", "KH", "KHM"}, AU: AU{"5102", "Cambodia", "116"}},
	Country{UN: UN{"120", "Cameroon", "CM", "CMR"}, AU: AU{"9103", "Cameroon", "120"}},
	Country{UN: UN{"124", "Canada", "CA", "CAN"}, AU: AU{"8102", "Canada", "124"}},
	Country{UN: UN{"136", "Cayman Islands", "KY", "CYM"}, AU: AU{"8406", "Cayman Islands", "136"}},
	Country{UN: UN{"140", "Central African Republic", "CF", "CAF"}, AU: AU{"9105", "Central African Republic", "140"}},
	Country{UN: UN{"148", "Chad", "TD", "TCD"}, AU: AU{"9106", "Chad", "148"}},
	Country{UN: UN{"152", "Chile", "CL", "CHL"}, AU: AU{"8204", "Chile", "152"}},
	Country{UN: UN{"156", "China", "CN", "CHN"}, AU: AU{"6101", "China (excludes SARs and Taiwan)", "156"}},
	Country{UN: UN{"162", "Christmas Island", "CX", "CXR"}, AU: AU{"", "", ""}},
	Country{UN: UN{"166", "Cocos (Keeling) Islands", "CC", "CCK"}, AU: AU{"", "", ""}},
	Country{UN: UN{"170", "Colombia", "CO", "COL"}, AU: AU{"8205", "Colombia", "170"}},
	Country{UN: UN{"174", "Comoros", "KM", "COM"}, AU: AU{"9204", "Comoros", "174"}},
	Country{UN: UN{"178", "Congo", "CG", "COG"}, AU: AU{"9107", "Congo, Republic of", "178"}},
	Country{UN: UN{"180", "Congo, Democratic Republic of the", "CD", "COD"}, AU: AU{"9108", "Congo, Democratic Republic of", "180"}},
	Country{UN: UN{"184", "Cook Islands", "CK", "COK"}, AU: AU{"1501", "Cook Islands", "184"}},
	Country{UN: UN{"188", "Costa Rica", "CR", "CRI"}, AU: AU{"8302", "Costa Rica", "188"}},
	Country{UN: UN{"384", "Côte d'Ivoire", "CI", "CIV"}, AU: AU{"9111", "Cote d'Ivoire", "384"}},
	Country{UN: UN{"191", "Croatia", "HR", "HRV"}, AU: AU{"3204", "Croatia", "191"}},
	Country{UN: UN{"192", "Cuba", "CU", "CUB"}, AU: AU{"8407", "Cuba", "192"}},
	Country{UN: UN{"531", "Curaçao", "CW", "CUW"}, AU: AU{"8434", "Curacao", "531"}},
	Country{UN: UN{"196", "Cyprus", "CY", "CYP"}, AU: AU{"3205", "Cyprus", "196"}},
	Country{UN: UN{"203", "Czechia", "CZ", "CZE"}, AU: AU{"3302", "Czechia", "203"}},
	Country{UN: UN{"208", "Denmark", "DK", "DNK"}, AU: AU{"2401", "Denmark", "208"}},
	Country{UN: UN{"262", "Djibouti", "DJ", "DJI"}, AU: AU{"9205", "Djibouti", "262"}},
	Country{UN: UN{"212", "Dominica", "DM", "DMA"}, AU: AU{"8408", "Dominica", "212"}},
	Country{UN: UN{"214", "Dominican Republic", "DO", "DOM"}, AU: AU{"8411", "Dominican Republic", "214"}},
	Country{UN: UN{"218", "Ecuador", "EC", "ECU"}, AU: AU{"8206", "Ecuador", "218"}},
	Country{UN: UN{"818", "Egypt", "EG", "EGY"}, AU: AU{"4102", "Egypt", "818"}},
	Country{UN: UN{"222", "El Salvador", "SV", "SLV"}, AU: AU{"8303", "El Salvador", "222"}},
	Country{UN: UN{"226", "Equatorial Guinea", "GQ", "GNQ"}, AU: AU{"9112", "Equatorial Guinea", "226"}},
	Country{UN: UN{"232", "Eritrea", "ER", "ERI"}, AU: AU{"9206", "Eritrea", "232"}},
	Country{UN: UN{"233", "Estonia", "EE", "EST"}, AU: AU{"3303", "Estonia", "233"}},
	Country{UN: UN{"748", "Eswatini", "SZ", "SWZ"}, AU: AU{"9226", "Eswatini", "748"}},
	Country{UN: UN{"231", "Ethiopia", "ET", "ETH"}, AU: AU{"9207", "Ethiopia", "231"}},
	Country{UN: UN{"238", "Falkland Islands (Malvinas)", "FK", "FLK"}, AU: AU{"8207", "Falkland Islands", "238"}},
	Country{UN: UN{"234", "Faroe Islands", "FO", "FRO"}, AU: AU{"2402", "Faroe Islands", "234"}},
	Country{UN: UN{"242", "Fiji", "FJ", "FJI"}, AU: AU{"1502", "Fiji", "242"}},
	Country{UN: UN{"246", "Finland", "FI", "FIN"}, AU: AU{"2403", "Finland", "246"}},
	Country{UN: UN{"250", "France", "FR", "FRA"}, AU: AU{"2303", "France", "250"}},
	Country{UN: UN{"254", "French Guiana", "GF", "GUF"}, AU: AU{"8208", "French Guiana", "254"}},
	Country{UN: UN{"258", "French Polynesia", "PF", "PYF"}, AU: AU{"1503", "French Polynesia", "258"}},
	Country{UN: UN{"260", "French Southern Territories", "TF", "ATF"}, AU: AU{"", "", ""}},
	Country{UN: UN{"266", "Gabon", "GA", "GAB"}, AU: AU{"9113", "Gabon", "266"}},
	Country{UN: UN{"270", "Gambia", "GM", "GMB"}, AU: AU{"9114", "Gambia", "270"}},
	Country{UN: UN{"268", "Georgia", "GE", "GEO"}, AU: AU{"7204", "Georgia", "268"}},
	Country{UN: UN{"276", "Germany", "DE", "DEU"}, AU: AU{"2304", "Germany", "276"}},
	Country{UN: UN{"288", "Ghana", "GH", "GHA"}, AU: AU{"9115", "Ghana", "288"}},
	Country{UN: UN{"292", "Gibraltar", "GI", "GIB"}, AU: AU{"3102", "Gibraltar", "292"}},
	Country{UN: UN{"300", "Greece", "GR", "GRC"}, AU: AU{"3207", "Greece", "300"}},
	Country{UN: UN{"304", "Greenland", "GL", "GRL"}, AU: AU{"2404", "Greenland", "304"}},
	Country{UN: UN{"308", "Grenada", "GD", "GRD"}, AU: AU{"8412", "Grenada", "308"}},
	Country{UN: UN{"312", "Guadeloupe", "GP", "GLP"}, AU: AU{"8413", "Guadeloupe", "312"}},
	Country{UN: UN{"316", "Guam", "GU", "GUM"}, AU: AU{"1401", "Guam", "316"}},
	Country{UN: UN{"320", "Guatemala", "GT", "GTM"}, AU: AU{"8304", "Guatemala", "320"}},
	Country{UN: UN{"831", "Guernsey", "GG", "GGY"}, AU: AU{"2107", "Guernsey", "831"}},
	Country{UN: UN{"324", "Guinea", "GN", "GIN"}, AU: AU{"9116", "Guinea", "324"}},
	Country{UN: UN{"624", "Guinea-Bissau", "GW", "GNB"}, AU: AU{"9117", "Guinea-Bissau", "624"}},
	Country{UN: UN{"328", "Guyana", "GY", "GUY"}, AU: AU{"8211", "Guyana", "328"}},
	Country{UN: UN{"332", "Haiti", "HT", "HTI"}, AU: AU{"8414", "Haiti", "332"}},
	Country{UN: UN{"334", "Heard Island and McDonald Islands", "HM", "HMD"}, AU: AU{"", "", ""}},
	Country{UN: UN{"336", "Holy See", "VA", "VAT"}, AU: AU{"3103", "Holy See", "336"}},
	Country{UN: UN{"340", "Honduras", "HN", "HND"}, AU: AU{"8305", "Honduras", "340"}},
	Country{UN: UN{"344", "Hong Kong", "HK", "HKG"}, AU: AU{"6102", "Hong Kong (SAR of China)", "344"}},
	Country{UN: UN{"348", "Hungary", "HU", "HUN"}, AU: AU{"3304", "Hungary", "348"}},
	Country{UN: UN{"352", "Iceland", "IS", "ISL"}, AU: AU{"2405", "Iceland", "352"}},
	Country{UN: UN{"356", "India", "IN", "IND"}, AU: AU{"7103", "India", "356"}},
	Country{UN: UN{"360", "Indonesia", "ID", "IDN"}, AU: AU{"5202", "Indonesia", "360"}},
	Country{UN: UN{"364", "Iran (Islamic Republic of)", "IR", "IRN"}, AU: AU{"4203", "Iran", "364"}},
	Country{UN: UN{"368", "Iraq", "IQ", "IRQ"}, AU: AU{"4204", "Iraq", "368"}},
	Country{UN: UN{"372", "Ireland", "IE", "IRL"}, AU: AU{"2201", "Ireland", "372"}},
	Country{UN: UN{"833", "Isle of Man", "IM", "IMN"}, AU: AU{"2103", "Isle of Man", "833"}},
	Country{UN: UN{"376", "Israel", "IL", "ISR"}, AU: AU{"4205", "Israel", "376"}},
	Country{UN: UN{"380", "Italy", "IT", "ITA"}, AU: AU{"3104", "Italy", "380"}},
	Country{UN: UN{"388", "Jamaica", "JM", "JAM"}, AU: AU{"8415", "Jamaica", "388"}},
	Country{UN: UN{"392", "Japan", "JP", "JPN"}, AU: AU{"6201", "Japan", "392"}},
	Country{UN: UN{"832", "Jersey", "JE", "JEY"}, AU: AU{"2108", "Jersey", "832"}},
	Country{UN: UN{"400", "Jordan", "JO", "JOR"}, AU: AU{"4206", "Jordan", "400"}},
	Country{UN: UN{"398", "Kazakhstan", "KZ", "KAZ"}, AU: AU{"7205", "Kazakhstan", "398"}},
	Country{UN: UN{"404", "Kenya", "KE", "KEN"}, AU: AU{"9208", "Kenya", "404"}},
	Country{UN: UN{"296", "Kiribati", "KI", "KIR"}, AU: AU{"1402", "Kiribati", "296"}},
	Country{UN: UN{"408", "Korea (Democratic People's Republic of)", "KP", "PRK"}, AU: AU{"6202", "Korea, Democratic People's Republic of (North)", "408"}},
	Country{UN: UN{"410", "Korea, Republic of", "KR", "KOR"}, AU: AU{"6203", "Korea, Republic of (South)", "410"}},
	Country{UN: UN{"414", "Kuwait", "KW", "KWT"}, AU: AU{"4207", "Kuwait", "414"}},
	Country{UN: UN{"417", "Kyrgyzstan", "KG", "KGZ"}, AU: AU{"7206", "Kyrgyzstan", "417"}},
	Country{UN: UN{"418", "Lao People's Democratic Republic", "LA", "LAO"}, AU: AU{"5103", "Laos", "418"}},
	Country{UN: UN{"428", "Latvia", "LV", "LVA"}, AU: AU{"3305", "Latvia", "428"}},
	Country{UN: UN{"422", "Lebanon", "LB", "LBN"}, AU: AU{"4208", "Lebanon", "422"}},
	Country{UN: UN{"426", "Lesotho", "LS", "LSO"}, AU: AU{"9211", "Lesotho", "426"}},
	Country{UN: UN{"430", "Liberia", "LR", "LBR"}, AU: AU{"9118", "Liberia", "430"}},
	Country{UN: UN{"434", "Libya", "LY", "LBY"}, AU: AU{"4103", "Libya", "434"}},
	Country{UN: UN{"438", "Liechtenstein", "LI", "LIE"}, AU: AU{"2305", "Liechtenstein", "438"}},
	Country{UN: UN{"440", "Lithuania", "LT", "LTU"}, AU: AU{"3306", "Lithuania", "440"}},
	Country{UN: UN{"442", "Luxembourg", "LU", "LUX"}, AU: AU{"2306", "Luxembourg", "442"}},
	Country{UN: UN{"446", "Macao", "MO", "MAC"}, AU: AU{"6103", "Macau (SAR of China)", "446"}},
	Country{UN: UN{"450", "Madagascar", "MG", "MDG"}, AU: AU{"9212", "Madagascar", "450"}},
	Country{UN: UN{"454", "Malawi", "MW", "MWI"}, AU: AU{"9213", "Malawi", "454"}},
	Country{UN: UN{"458", "Malaysia", "MY", "MYS"}, AU: AU{"5203", "Malaysia", "458"}},
	Country{UN: UN{"462", "Maldives", "MV", "MDV"}, AU: AU{"7104", "Maldives", "462"}},
	Country{UN: UN{"466", "Mali", "ML", "MLI"}, AU: AU{"9121", "Mali", "466"}},
	Country{UN: UN{"470", "Malta", "MT", "MLT"}, AU: AU{"3105", "Malta", "470"}},
	Country{UN: UN{"584", "Marshall Islands", "MH", "MHL"}, AU: AU{"1403", "Marshall Islands", "584"}},
	Country{UN: UN{"474", "Martinique", "MQ", "MTQ"}, AU: AU{"8416", "Martinique", "474"}},
	Country{UN: UN{"478", "Mauritania", "MR", "MRT"}, AU: AU{"9122", "Mauritania", "478"}},
	Country{UN: UN{"480", "Mauritius", "MU", "MUS"}, AU: AU{"9214", "Mauritius", "480"}},
	Country{UN: UN{"175", "Mayotte", "YT", "MYT"}, AU: AU{"9215", "Mayotte", "175"}},
	Country{UN: UN{"484", "Mexico", "MX", "MEX"}, AU: AU{"8306", "Mexico", "484"}},
	Country{UN: UN{"583", "Micronesia (Federated States of)", "FM", "FSM"}, AU: AU{"1404", "Micronesia, Federated States of", "583"}},
	Country{UN: UN{"498", "Moldova, Republic of", "MD", "MDA"}, AU: AU{"3208", "Moldova", "498"}},
	Country{UN: UN{"492", "Monaco", "MC", "MCO"}, AU: AU{"2307", "Monaco", "492"}},
	Country{UN: UN{"496", "Mongolia", "MN", "MNG"}, AU: AU{"6104", "Mongolia", "496"}},
	Country{UN: UN{"499", "Montenegro", "ME", "MNE"}, AU: AU{"3214", "Montenegro", "499"}},
	Country{UN: UN{"500", "Montserrat", "MS", "MSR"}, AU: AU{"8417", "Montserrat", "500"}},
	Country{UN: UN{"504", "Morocco", "MA", "MAR"}, AU: AU{"4104", "Morocco", "504"}},
	Country{UN: UN{"508", "Mozambique", "MZ", "MOZ"}, AU: AU{"9216", "Mozambique", "508"}},
	Country{UN: UN{"104", "Myanmar", "MM", "MMR"}, AU: AU{"5101", "Myanmar", "104"}},
	Country{UN: UN{"516", "Namibia", "NA", "NAM"}, AU: AU{"9217", "Namibia", "516"}},
	Country{UN: UN{"520", "Nauru", "NR", "NRU"}, AU: AU{"1405", "Nauru", "520"}},
	Country{UN: UN{"524", "Nepal", "NP", "NPL"}, AU: AU{"7105", "Nepal", "524"}},
	Country{UN: UN{"528", "Netherlands", "NL", "NLD"}, AU: AU{"2308", "Netherlands", "528"}},
	Country{UN: UN{"540", "New Caledonia", "NC", "NCL"}, AU: AU{"1301", "New Caledonia", "540"}},
	Country{UN: UN{"554", "New Zealand", "NZ", "NZL"}, AU: AU{"1201", "New Zealand", "554"}},
	Country{UN: UN{"558", "Nicaragua", "NI", "NIC"}, AU: AU{"8307", "Nicaragua", "558"}},
	Country{UN: UN{"562", "Niger", "NE", "NER"}, AU: AU{"9123", "Niger", "562"}},
	Country{UN: UN{"566", "Nigeria", "NG", "NGA"}, AU: AU{"9124", "Nigeria", "566"}},
	Country{UN: UN{"570", "Niue", "NU", "NIU"}, AU: AU{"1504", "Niue", "570"}},
	Country{UN: UN{"574", "Norfolk Island", "NF", "NFK"}, AU: AU{"1102", "Norfolk Island", "574"}},
	Country{UN: UN{"807", "North Macedonia", "MK", "MKD"}, AU: AU{"3206", "North Macedonia", "807"}},
	Country{UN: UN{"580", "Northern Mariana Islands", "MP", "MNP"}, AU: AU{"1406", "Northern Mariana Islands", "580"}},
	Country{UN: UN{"578", "Norway", "NO", "NOR"}, AU: AU{"2406", "Norway", "578"}},
	Country{UN: UN{"512", "Oman", "OM", "OMN"}, AU: AU{"4211", "Oman", "512"}},
	Country{UN: UN{"586", "Pakistan", "PK", "PAK"}, AU: AU{"7106", "Pakistan", "586"}},
	Country{UN: UN{"585", "Palau", "PW", "PLW"}, AU: AU{"1407", "Palau", "585"}},
	Country{UN: UN{"275", "Palestine, State of", "PS", "PSE"}, AU: AU{"4202", "Gaza Strip and West Bank", "275"}},
	Country{UN: UN{"591", "Panama", "PA", "PAN"}, AU: AU{"8308", "Panama", "591"}},
	Country{UN: UN{"598", "Papua New Guinea", "PG", "PNG"}, AU: AU{"1302", "Papua New Guinea", "598"}},
	Country{UN: UN{"600", "Paraguay", "PY", "PRY"}, AU: AU{"8212", "Paraguay", "600"}},
	Country{UN: UN{"604", "Peru", "PE", "PER"}, AU: AU{"8213", "Peru", "604"}},
	Country{UN: UN{"608", "Philippines", "PH", "PHL"}, AU: AU{"5204", "Philippines", "608"}},
	Country{UN: UN{"612", "Pitcairn", "PN", "PCN"}, AU: AU{"1513", "Pitcairn Islands", "612"}},
	Country{UN: UN{"616", "Poland", "PL", "POL"}, AU: AU{"3307", "Poland", "616"}},
	Country{UN: UN{"620", "Portugal", "PT", "PRT"}, AU: AU{"3106", "Portugal", "620"}},
	Country{UN: UN{"630", "Puerto Rico", "PR", "PRI"}, AU: AU{"8421", "Puerto Rico", "630"}},
	Country{UN: UN{"634", "Qatar", "QA", "QAT"}, AU: AU{"4212", "Qatar", "634"}},
	Country{UN: UN{"638", "Réunion", "RE", "REU"}, AU: AU{"9218", "Reunion", "638"}},
	Country{UN: UN{"642", "Romania", "RO", "ROU"}, AU: AU{"3211", "Romania", "642"}},
	Country{UN: UN{"643", "Russian Federation", "RU", "RUS"}, AU: AU{"3308", "Russian Federation", "643"}},
	Country{UN: UN{"646", "Rwanda", "RW", "RWA"}, AU: AU{"9221", "Rwanda", "646"}},
	Country{UN: UN{"652", "Saint Barthélemy", "BL", "BLM"}, AU: AU{"8431", "St Barthelemy", "652"}},
	Country{UN: UN{"654", "Saint Helena, Ascension and Tristan da Cunha", "SH", "SHN"}, AU: AU{"9222", "St Helena", "654"}},
	Country{UN: UN{"659", "Saint Kitts and Nevis", "KN", "KNA"}, AU: AU{"8422", "St Kitts and Nevis", "659"}},
	Country{UN: UN{"662", "Saint Lucia", "LC", "LCA"}, AU: AU{"8423", "St Lucia", "662"}},
	Country{UN: UN{"663", "Saint Martin (French part)", "MF", "MAF"}, AU: AU{"8432", "St Martin (French part)", "663"}},
	Country{UN: UN{"666", "Saint Pierre and Miquelon", "PM", "SPM"}, AU: AU{"8103", "St Pierre and Miquelon", "666"}},
	Country{UN: UN{"670", "Saint Vincent and the Grenadines", "VC", "VCT"}, AU: AU{"8424", "St Vincent and the Grenadines", "670"}},
	Country{UN: UN{"882", "Samoa", "WS", "WSM"}, AU: AU{"1505", "Samoa", "882"}},
	Country{UN: UN{"674", "San Marino", "SM", "SMR"}, AU: AU{"3107", "San Marino", "674"}},
	Country{UN: UN{"678", "Sao Tome and Principe", "ST", "STP"}, AU: AU{"9125", "Sao Tome and Principe", "678"}},
	Country{UN: UN{"682", "Saudi Arabia", "SA", "SAU"}, AU: AU{"4213", "Saudi Arabia", "682"}},
	Country{UN: UN{"686", "Senegal", "SN", "SEN"}, AU: AU{"9126", "Senegal", "686"}},
	Country{UN: UN{"688", "Serbia", "RS", "SRB"}, AU: AU{"3215", "Serbia", "688"}},
	Country{UN: UN{"690", "Seychelles", "SC", "SYC"}, AU: AU{"9223", "Seychelles", "690"}},
	Country{UN: UN{"694", "Sierra Leone", "SL", "SLE"}, AU: AU{"9127", "Sierra Leone", "694"}},
	Country{UN: UN{"702", "Singapore", "SG", "SGP"}, AU: AU{"5205", "Singapore", "702"}},
	Country{UN: UN{"534", "Sint Maarten (Dutch part)", "SX", "SXM"}, AU: AU{"8435", "Sint Maarten (Dutch part)", "534"}},
	Country{UN: UN{"703", "Slovakia", "SK", "SVK"}, AU: AU{"3311", "Slovakia", "703"}},
	Country{UN: UN{"705", "Slovenia", "SI", "SVN"}, AU: AU{"3212", "Slovenia", "705"}},
	Country{UN: UN{"090", "Solomon Islands", "SB", "SLB"}, AU: AU{"1303", "Solomon Islands", "090"}},
	Country{UN: UN{"706", "Somalia", "SO", "SOM"}, AU: AU{"9224", "Somalia", "706"}},
	Country{UN: UN{"710", "South Africa", "ZA", "ZAF"}, AU: AU{"9225", "South Africa", "710"}},
	Country{UN: UN{"239", "South Georgia and the South Sandwich Islands", "GS", "SGS"}, AU: AU{"", "", ""}},
	Country{UN: UN{"728", "South Sudan", "SS", "SSD"}, AU: AU{"4111", "South Sudan", "728"}},
	Country{UN: UN{"724", "Spain", "ES", "ESP"}, AU: AU{"3108", "Spain", "724"}},
	Country{UN: UN{"144", "Sri Lanka", "LK", "LKA"}, AU: AU{"7107", "Sri Lanka", "144"}},
	Country{UN: UN{"729", "Sudan", "SD", "SDN"}, AU: AU{"4105", "Sudan", "729"}},
	Country{UN: UN{"740", "Suriname", "SR", "SUR"}, AU: AU{"8214", "Suriname", "740"}},
	Country{UN: UN{"744", "Svalbard and Jan Mayen", "SJ", "SJM"}, AU: AU{"", "", ""}},
	Country{UN: UN{"752", "Sweden", "SE", "SWE"}, AU: AU{"2407", "Sweden", "752"}},
	Country{UN: UN{"756", "Switzerland", "CH", "CHE"}, AU: AU{"2311", "Switzerland", "756"}},
	Country{UN: UN{"760", "Syrian Arab Republic", "SY", "SYR"}, AU: AU{"4214", "Syria", "760"}},
	Country{UN: UN{"158", "Taiwan, Province of China", "TW", "TWN"}, AU: AU{"6105", "Taiwan", "158"}},
	Country{UN: UN{"762", "Tajikistan", "TJ", "TJK"}, AU: AU{"7207", "Tajikistan", "762"}},
	Country{UN: UN{"834", "Tanzania, United Republic of", "TZ", "TZA"}, AU: AU{"9227", "Tanzania", "834"}},
	Country{UN: UN{"764", "Thailand", "TH", "THA"}, AU: AU{"5104", "Thailand", "764"}},
	Country{UN: UN{"626", "Timor-Leste", "TL", "TLS"}, AU: AU{"5206", "Timor-Leste", "626"}},
	Country{UN: UN{"768", "Togo", "TG", "TGO"}, AU: AU{"9128", "Togo", "768"}},
	Country{UN: UN{"772", "Tokelau", "TK", "TKL"}, AU: AU{"1507", "Tokelau", "772"}},
	Country{UN: UN{"776", "Tonga", "TO", "TON"}, AU: AU{"1508", "Tonga", "776"}},
	Country{UN: UN{"780", "Trinidad and Tobago", "TT", "TTO"}, AU: AU{"8425", "Trinidad and Tobago", "780"}},
	Country{UN: UN{"788", "Tunisia", "TN", "TUN"}, AU: AU{"4106", "Tunisia", "788"}},
	Country{UN: UN{"792", "Turkey", "TR", "TUR"}, AU: AU{"4215", "Turkey", "792"}},
	Country{UN: UN{"795", "Turkmenistan", "TM", "TKM"}, AU: AU{"7208", "Turkmenistan", "795"}},
	Country{UN: UN{"796", "Turks and Caicos Islands", "TC", "TCA"}, AU: AU{"8426", "Turks and Caicos Islands", "796"}},
	Country{UN: UN{"798", "Tuvalu", "TV", "TUV"}, AU: AU{"1511", "Tuvalu", "798"}},
	Country{UN: UN{"800", "Uganda", "UG", "UGA"}, AU: AU{"9228", "Uganda", "800"}},
	Country{UN: UN{"804", "Ukraine", "UA", "UKR"}, AU: AU{"3312", "Ukraine", "804"}},
	Country{UN: UN{"784", "United Arab Emirates", "AE", "ARE"}, AU: AU{"4216", "United Arab Emirates", "784"}},
	Country{UN: UN{"826", "United Kingdom of Great Britain and Northern Ireland", "GB", "GBR"}, AU: AU{"2106", "Wales", "826"}},
	Country{UN: UN{"840", "United States of America", "US", "USA"}, AU: AU{"8104", "United States of America", "840"}},
	Country{UN: UN{"581", "United States Minor Outlying Islands", "UM", "UMI"}, AU: AU{"", "", ""}},
	Country{UN: UN{"858", "Uruguay", "UY", "URY"}, AU: AU{"8215", "Uruguay", "858"}},
	Country{UN: UN{"860", "Uzbekistan", "UZ", "UZB"}, AU: AU{"7211", "Uzbekistan", "860"}},
	Country{UN: UN{"548", "Vanuatu", "VU", "VUT"}, AU: AU{"1304", "Vanuatu", "548"}},
	Country{UN: UN{"862", "Venezuela (Bolivarian Republic of)", "VE", "VEN"}, AU: AU{"8216", "Venezuela", "862"}},
	Country{UN: UN{"704", "Viet Nam", "VN", "VNM"}, AU: AU{"5105", "Vietnam", "704"}},
	Country{UN: UN{"092", "Virgin Islands (British)", "VG", "VGB"}, AU: AU{"8427", "Virgin Islands, British", "092"}},
	Country{UN: UN{"850", "Virgin Islands (U.S.)", "VI", "VIR"}, AU: AU{"8428", "Virgin Islands, United States", "850"}},
	Country{UN: UN{"876", "Wallis and Futuna", "WF", "WLF"}, AU: AU{"1512", "Wallis and Futuna", "876"}},
	Country{UN: UN{"732", "Western Sahara", "EH", "ESH"}, AU: AU{"4107", "Western Sahara", "732"}},
	Country{UN: UN{"887", "Yemen", "YE", "YEM"}, AU: AU{"4217", "Yemen", "887"}},
	Country{UN: UN{"894", "Zambia", "ZM", "ZMB"}, AU: AU{"9231", "Zambia", "894"}},
	Country{UN: UN{"716", "Zimbabwe", "ZW", "ZWE"}, AU: AU{"9232", "Zimbabwe", "716"}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1599", "Polynesia (excludes Hawaii), nec", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1601", "Adelie Land (France)", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1602", "Argentinian Antarctic Territory", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1603", "Australian Antarctic Territory", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1604", "British Antarctic Territory", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1605", "Chilean Antarctic Territory", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1606", "Queen Maud Land (Norway)", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"1607", "Ross Dependency (New Zealand)", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"3216", "Kosovo", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"4108", "Spanish North Africa", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"8299", "South America, nec", ""}},
	Country{UN: UN{"", "", "", ""}, AU: AU{"9299", "Southern and East Africa, nec", ""}},
}
