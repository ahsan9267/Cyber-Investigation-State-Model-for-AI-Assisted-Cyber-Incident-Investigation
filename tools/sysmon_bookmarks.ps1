# Bookmark compatibility helpers for Windows PowerShell 5.1.

if (-not ("Spine.EventBookmarkCompat" -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Diagnostics.Eventing.Reader;
using System.Runtime.Serialization;

namespace Spine
{
    public sealed class EventBookmarkCompat : EventBookmark
    {
        private EventBookmarkCompat(
            SerializationInfo info,
            StreamingContext context
        ) : base(info, context)
        {
        }

        public static string Export(EventBookmark bookmark)
        {
            if (bookmark == null)
                throw new ArgumentNullException("bookmark");

            var info = new SerializationInfo(
                typeof(EventBookmark),
                new FormatterConverter()
            );

            ((ISerializable)bookmark).GetObjectData(
                info,
                new StreamingContext(StreamingContextStates.All)
            );

            return info.GetString("BookmarkText");
        }

        public static EventBookmark Restore(string bookmarkText)
        {
            if (String.IsNullOrWhiteSpace(bookmarkText))
                throw new ArgumentException("Bookmark text is empty");

            var info = new SerializationInfo(
                typeof(EventBookmark),
                new FormatterConverter()
            );

            info.AddValue("BookmarkText", bookmarkText);

            return new EventBookmarkCompat(
                info,
                new StreamingContext(StreamingContextStates.All)
            );
        }
    }
}
'@
}