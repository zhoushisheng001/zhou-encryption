package com.zhuguang.zhou.vo;

import java.util.HashMap;
import java.util.Map;

public class RestResultVo {
	private String status = "1";// 1 成功 0 失败
	private String messageCode;// 错误消息代码
	private String message;
	private Object data;
	private Map<String, Object> map = new HashMap<String, Object>();

	public String getStatus() {
		return status;
	}

	public void setStatus(String status) {
		this.status = status;
	}

	public String getMessageCode() {
		return messageCode;
	}

	public void setMessageCode(String messageCode) {
		this.messageCode = messageCode;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public Object getData() {
		return data;
	}

	public void setData(Object data) {
		this.data = data;
	}

	public Map<String, Object> getMap() {
		return map;
	}

	public void setMap(Map<String, Object> map) {
		this.map = map;
	}
	
	public void setValue(String key, String value){
		this.map.put(key, value);
	}
	
	public Object getValue(String key){
		return this.map.get(key);
	}

}
