package security

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

func ipLookupTask(am AccessManager) func(session Session, message map[string]interface{}) error {
	return func(session Session, message map[string]interface{}) error {

		/* No Timezone info
				address := session.IP()
				apikey := "55db09a5221098b3528fef1c8275195f"
				url := "http://api.ipstack.com/" + address + "?access_key=" + apikey + "&format=1"
				fmt.Println(url)

				am.Debug(session, `auth`, "Task(%s): Looking up ip: %s", message["type"].(string), address)

				response, err := http.Get(url)
				if err != nil {
					fmt.Println(err)
				}

				defer response.Body.Close()

				body, err := ioutil.ReadAll(response.Body)
				if err != nil {
					fmt.Println(err)
				}
				fmt.Println(string(body))

		type GeoIP struct {
			Ip          string  `json:"ip"`
			CountryCode string  `json:"country_code"`
			CountryName string  `json:"country_name""`
			RegionCode  string  `json:"region_code"`
			RegionName  string  `json:"region_name"`
			City        string  `json:"city"`
			Lat         float32 `json:"latitude"`
			Lon         float32 `json:"longitude"`
		}

				var geo GeoIP
				err = json.Unmarshal(body, &geo)
				if err != nil {
					fmt.Println(err)
				}

				fmt.Println("==== IP Geolocation Info ====")
				fmt.Println("IP address:", geo.Ip)
				fmt.Println("Country Code:", geo.CountryCode)
				fmt.Println("Country Name:", geo.CountryName)
				fmt.Println("Latitude:", geo.Lat)
				fmt.Println("Longitude:", geo.Lon)
				fmt.Println("Country:", geo.CountryName)
				fmt.Println("Region:", geo.RegionName)
		*/

		address := message["ip"].(string)
		apikey := "7a1efe3a2de431c490520c32b6618bf7d29f4d0f4f60f9a5a2ce177f"
		url := "https://api.ipdata.co/" + address + "?api-key=" + apikey
		am.Debug(session, `auth`, "Task(%s): Looking up ip: %s", message["type"].(string), address)

		response, err := http.Get(url)
		if err != nil {
			fmt.Println(err)
		}
		defer response.Body.Close()

		if response.StatusCode != 200 {
			am.Error(session, `auth`, "Task(%s): Looking up ip %s failed: status %d", message["type"].(string), address, response.StatusCode)
			return err
		}
		am.Debug(session, `auth`, "Task(%s): Looking up ip %s: status %d", message["type"].(string), address, response.StatusCode)

		body, err := ioutil.ReadAll(response.Body)
		if err != nil {
			am.Debug(session, `auth`, "Task(%s): Looking up ip %s failed: %v", message["type"].(string), address, err)
			fmt.Println(err)
			return err
		}

		type TZ struct {
			Name string `json:"name"`
		}
		type GeoIP struct {
			Ip           string  `json:"ip"`
			CountryCode  string  `json:"country_code"`
			CountryName  string  `json:"country_name"`
			RegionCode   string  `json:"region_code"`
			RegionName   string  `json:"region"`
			City         string  `json:"city"`
			Lat          float32 `json:"latitude"`
			Lon          float32 `json:"longitude"`
			Organisation string  `json:"organisation"`
			TimeZone     TZ      `json:"time_zone"`
		}

		var geo GeoIP
		err = json.Unmarshal(body, &geo)
		if err != nil {
			am.Debug(session, `auth`, "Task(%s): Looking up ip %s failed: %v", message["type"].(string), address, err)
			fmt.Println(err)
			return err
		}

		if geo.Ip == "" {
			am.Debug(session, `auth`, "Task(%s): Looking up ip %s failed: empty response", message["type"].(string), address)
			return err
		}

		/*
			fmt.Println("==== IP Geolocation Info ====")
			fmt.Println("IP address:", geo.Ip)
			fmt.Println("Country Code:", geo.CountryCode)
			fmt.Println("Country Name:", geo.CountryName)
			fmt.Println("Country:", geo.CountryName)
			fmt.Println("Region:", geo.RegionName)
			fmt.Println("City:", geo.City)
			fmt.Println("TimeZone:", geo.TimeZone.Name)
		*/

		return am.SaveIp(geo.Ip, geo.CountryName, geo.RegionName, geo.City, geo.TimeZone.Name, geo.Organisation)
	}
}
