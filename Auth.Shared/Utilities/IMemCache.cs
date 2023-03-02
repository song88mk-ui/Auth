using System.Collections;

namespace Auth.Shared.Utilities
{
    public interface IMemCache
    {
        void AddOrUpdateCache<T>(string key, T cacheObject, int cacheTimeout);

        void AddOrUpdateCache<T>(string key, T cacheObject, DateTimeOffset date);

        T GetCache<T>(string key, Func<T> repositoryCall, int expiration) where T : class;

        T GetCache<T>(string key) where T : class;
        List<T> GetCache<T>() where T : class;

        KeyValuePair<bool, long> GetCache(string key);
        void DeleteCache(string key);
        List<T> GetAllCache<T>(string prefix = "");
    }
}
