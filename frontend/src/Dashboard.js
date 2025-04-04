import React, { useState, useEffect } from "react";
import axios from "axios";

function Dashboard() {
	const [ssid, setSsid] = useState("");
	const [password, setPassword] = useState("");
	const [devices, setDevices] = useState([]);
	const [credentials, setCredentials] = useState([]);

	const startAP = async () => {
		await axios.post("/start_ap", { ssid, password });
		alert("Rogue AP started!");
	};
	const resetSettings = async () => {
		try {
			const response = await axios.post("/reset");
			alert(response.data.message);
		} catch (error) {
			alert(
				"Reset failed: " +
					(error.response?.data?.details?.join(", ") || "Unknown error")
			);
		}
	};

	useEffect(() => {
		const interval = setInterval(async () => {
			const devRes = await axios.get("/devices");
			const credRes = await axios.get("/credentials");
			setDevices(devRes.data);
			setCredentials(credRes.data);
		}, 2000);
		return () => clearInterval(interval);
	}, []);

	return <></>;
}

export default Dashboard;
