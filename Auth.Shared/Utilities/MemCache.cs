using Microsoft.EntityFrameworkCore.Metadata.Internal;
using System.Collections;
using System.Runtime.Caching;

namespace Auth.Shared.Utilities
{
    public class MemCache : IMemCache
    {
        public void AddOrUpdateCache<T>(string key, T cacheObject, int cacheTimeout)
        {
            MemoryCache.Default.Set(key, cacheObject, new CacheItemPolicy
            {
                AbsoluteExpiration = DateTimeOffset.Now.AddHours(cacheTimeout)
            });
        }

        public void AddOrUpdateCache<T>(string key, T cacheObject, DateTimeOffset date)
        {
            MemoryCache.Default.Set(key, cacheObject, new CacheItemPolicy
            {
                AbsoluteExpiration = date
            });
        }

        public T GetCache<T>(string key, Func<T> repositoryCall, int expiration) where T : class
        {
            var result = (T)MemoryCache.Default.Get(key);

            if (result == null && repositoryCall != null)
            {
                result = repositoryCall();

                if (result != null)
                    AddOrUpdateCache(key, result, expiration);
            }

            return result;
        }

        public KeyValuePair<bool, long> GetCache(string key)
        {
            var result = MemoryCache.Default.Get(key);

            return result == null ? new KeyValuePair<bool, long>(false, 0) : (KeyValuePair<bool, long>)result;
        }
        public List<T> GetCache<T>() where T : class
        {
            var cached = MemoryCache.Default;

            var result = new List<T>();

            foreach (var item in cached)
            {
                result.Add((T)item.Value);
            }

            return result;
        }

        public T GetCache<T>(string key) where T : class
        {
            var result = (T)MemoryCache.Default.Get(key);

            return result;
        }
        public virtual List<T> GetAllCache<T>(string prefix = "")
        {
            List<T> list = new List<T>();

            var cached = MemoryCache.Default.Where(x => x.Key.StartsWith(prefix));

            var result = new List<T>();

            foreach (var item in cached)
            {
                result.Add((T)item.Value);
            }
            return result;
        }

        public void DeleteCache(string key)
        {
            MemoryCache.Default.Remove(key);
        }
    }
}
