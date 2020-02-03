using System;
using System.Collections.Generic;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using AlibabaCloud.RPC.Utils;
using System.Linq;
using System.Text;
using System.Threading;
using Tea;
using System.Web;
using System.Security.Cryptography;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Globalization;

namespace AlibabaCloud.RPC
{
    public class RPCClient
    {
        private const string SEPARATOR = "&";
        private const string ALGORITHM_NAME = "HMACSHA1";
        protected string _domain;
        protected string _endpoint;
        protected string _authToken;
        protected string _regionId;
        protected string _protocol;
        protected string _userAgent;
        protected int? _readTimeout;
        protected int? _connectTimeout;
        protected string _httpProxy;
        protected string _httpsProxy;
        protected string _noProxy;
        protected int? _maxIdleConns;
        protected string _endpointType;

        private string _accessKeyId;
        private string _accessKeySecret;
        private readonly string _defaultUserAgent;
        private readonly Encoding URL_ENCODING = Encoding.UTF8;


        public RPCClient(Dictionary<string,object> config)
        {
            _domain = DictUtils.GetDicValue(config, "domain").ToSafeString();
            _endpoint = DictUtils.GetDicValue(config, "endpoint").ToSafeString();
            _authToken = DictUtils.GetDicValue(config, "authToken").ToSafeString();
            _accessKeyId = DictUtils.GetDicValue(config, "accessKeyId").ToSafeString();
            _accessKeySecret = DictUtils.GetDicValue(config, "accessKeySecret").ToSafeString();
            _userAgent = DictUtils.GetDicValue(config, "userAgent").ToSafeString();
            _regionId = DictUtils.GetDicValue(config, "regionId").ToSafeString();
            _readTimeout = DictUtils.GetDicValue(config, "readTimeout").ToSafeInt();
            _connectTimeout = DictUtils.GetDicValue(config, "connectTimeout").ToSafeInt();
            _httpProxy = DictUtils.GetDicValue(config, "httpProxy").ToSafeString();
            _httpsProxy = DictUtils.GetDicValue(config, "httpsProxy").ToSafeString();
            _noProxy = DictUtils.GetDicValue(config, "noProxy").ToSafeString();
            _maxIdleConns = DictUtils.GetDicValue(config, "maxIdleConns").ToSafeInt();
            _endpointType = DictUtils.GetDicValue(config, "endpointType").ToSafeString();
            _defaultUserAgent = GetDefaultUserAgent();
        }

        protected int _defaultNumber(object o, int number)
        {
            return o == null ? number : o.ToSafeInt(number);
        }

        protected string _default(object o, string str)
        {
            return o == null ? str : o.ToSafeString(str);
        }

        protected Dictionary<string, string> _query(Dictionary<string, object> dict)
        {
            Dictionary<string, string> outDict = new Dictionary<string, string>();
            foreach(var keypair in dict)
            {
                outDict.Add(keypair.Key, keypair.Value.ToSafeString(""));
            }
            return outDict;
        }

        protected string _getTimestamp()
        {
            return DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
        }

        protected string _getNonce()
        {
            StringBuilder uniqueNonce = new StringBuilder();
            Guid uuid = new Guid();
            uniqueNonce.Append(uuid.ToString());
            uniqueNonce.Append(DateTime.UtcNow.GetTimeMillis());
            uniqueNonce.Append(Thread.CurrentThread.ManagedThreadId);
            return uniqueNonce.ToString();
        }

        protected string _getSignature(TeaRequest request, string secret)
        {
            Dictionary<string, string> queries = request.Query;
            List<string> sortedKeys = queries.Keys.ToList();
            sortedKeys.Sort();
            StringBuilder canonicalizedQueryString = new StringBuilder();

            foreach (string key in sortedKeys)
            {
                canonicalizedQueryString.Append("&")
                        .Append(PercentEncode(key)).Append("=")
                        .Append(PercentEncode(queries[key]));
            }
            StringBuilder stringToSign = new StringBuilder();
            stringToSign.Append(request.Method);
            stringToSign.Append(SEPARATOR);
            stringToSign.Append(PercentEncode("/"));
            stringToSign.Append(SEPARATOR);
            stringToSign.Append(PercentEncode(
                        canonicalizedQueryString.ToString().Substring(1)));
            byte[] signData;
            using (KeyedHashAlgorithm algorithm = CryptoConfig.CreateFromName(ALGORITHM_NAME) as KeyedHashAlgorithm)
            {
                algorithm.Key = URL_ENCODING.GetBytes(secret+SEPARATOR);
                signData = algorithm.ComputeHash(URL_ENCODING.GetBytes(stringToSign.ToString().ToCharArray()));
            }
            string signedStr = Convert.ToBase64String(signData);
            return signedStr;
        }

        protected string _getAccessKeyId()
        {
            return _accessKeyId;
        }

        protected string _getAccessKeySecret()
        {
            return _accessKeySecret;
        }

        protected string _getUserAgent()
        {
            return this._getUserAgent(null);
        }

        protected string _getUserAgent(string userAgent)
        {
            if (string.IsNullOrWhiteSpace(userAgent))
            {
                return _defaultUserAgent;
            }
            return _defaultUserAgent + " " + userAgent;
        }

        protected string _getEndpoint(string str, string regionId)
        {
            if (null == _endpoint)
            {
                string serviceCode = str.Split('_')[0].ToLower();
                
                return string.Format("{0}.{1}.aliyuncs.com", serviceCode, regionId);
            }
            else
            {
                return _endpoint;
            }
        }

        protected bool _hasError(Dictionary<string, object> body)
        {
            if (null == body)
            {
                return true;
            }
            if (null == DictUtils.GetDicValue(body, "Code"))
            {
                return false;
            }
            return true;
        }

        protected Dictionary<string, object> _json(TeaResponse response)
        {
            string body = TeaCore.GetResponseBody(response);
            Dictionary<string, object> dic = new Dictionary<string, object>();
            Dictionary<string, object> dicBody = JsonConvert.DeserializeObject<Dictionary<string, object>>(body);
            dic = ObjToDictionary(dicBody);
            return dic;
        }

        internal Dictionary<string, object> ObjToDictionary(Dictionary<string, object> dicObj)
        {
            Dictionary<string, object> dic = new Dictionary<string, object>();
            foreach (string key in dicObj.Keys)
            {
                if (dicObj[key] is JArray)
                {
                    List<Dictionary<string, object>> dicObjList = ((JArray)dicObj[key]).ToObject<List<Dictionary<string, object>>>();
                    List<Dictionary<string, object>> dicList = new List<Dictionary<string, object>>();
                    foreach (Dictionary<string, object> objItem in dicObjList)
                    {
                        dicList.Add(ObjToDictionary(objItem));
                    }
                    dic.Add(key, dicList);
                }
                else if (dicObj[key] is JObject)
                {
                    Dictionary<string, object> dicJObj = ((JObject)dicObj[key]).ToObject<Dictionary<string, object>>();
                    dic.Add(key, dicJObj);
                }
                else
                {
                    dic.Add(key, dicObj[key]);
                }
            }
            return dic;
        }

        internal string PercentEncode(string value)
        {
            if(value == null)
            {
                return null;
            }
            var stringBuilder = new StringBuilder();
            var text = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
            var bytes = URL_ENCODING.GetBytes(value);
            foreach (char c in bytes)
            {
                if (text.IndexOf(c) >= 0)
                {
                    stringBuilder.Append(c);
                }
                else
                {
                    stringBuilder.Append("%").Append(string.Format(CultureInfo.InvariantCulture, "{0:X2}", (int)c));
                }
            }

            return stringBuilder.ToString().Replace("+", "%20")
                .Replace("*", "%2A").Replace("%7E", "~");
        }

        internal string GetDefaultUserAgent()
        {
            string defaultUserAgent = string.Empty;
            string OSVersion = Environment.OSVersion.ToString();
            string ClientVersion = GetRuntimeRegexValue(RuntimeEnvironment.GetRuntimeDirectory());
            string CoreVersion = Assembly.GetExecutingAssembly().GetName().Version.ToString();
            defaultUserAgent = "Alibaba Cloud (" + OSVersion + ") ";
            defaultUserAgent += ClientVersion;
            defaultUserAgent += " Core/" + CoreVersion;
            return defaultUserAgent;
        }

        internal string GetRuntimeRegexValue(string value)
        {
            var rx = new Regex(@"(\.NET).*(\\|\/).*(\d)", RegexOptions.Compiled | RegexOptions.IgnoreCase);
            var matches = rx.Match(value);
            char[] separator = { '\\', '/' };

            if (matches.Success)
            {
                var clientValueArray = matches.Value.Split(separator);
                return BuildClientVersion(clientValueArray);
            }

            return "RuntimeNotFound";
        }

        internal string BuildClientVersion(string[] value)
        {
            var finalValue = "";
            for (var i = 0; i < value.Length - 1; ++i)
            {
                finalValue += value[i].Replace(".", "").ToLower();
            }

            finalValue += "/" + value[value.Length - 1];

            return finalValue;
        }

    }
}