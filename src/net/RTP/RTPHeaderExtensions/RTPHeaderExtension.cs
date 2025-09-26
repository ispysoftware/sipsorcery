using System;
using System.Collections.Generic;
using System.Linq;

namespace SIPSorcery.Net
{
    public abstract class RTPHeaderExtension
    {
        /// <summary>
        /// Create an RTPHeaderExtension (<see cref="AbsSendTimeExtension"/>, <see cref="CVOExtension"/>, etc ...) based on the URI provided
        /// If found, id permits to store the "extmap" value related to this extension
        /// It not found returns null
        /// </summary>
        /// <param name="id">extmap value</param>
        /// <param name="uri">URI of the extension - for example: "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time" or "urn:3gpp:video-orientation" </param>
        /// <returns>A Specific RTPHeaderExtension</returns>
        public static RTPHeaderExtension GetRTPHeaderExtension(int id, string uri, SDPMediaTypesEnum media)
        {
            RTPHeaderExtension result = null;
            if (AbsSendTimeExtension.SUPPORTED_URIS.Contains(uri, StringComparer.InvariantCultureIgnoreCase))
            {
                result = new AbsSendTimeExtension(id);
            }
            else if (CVOExtension.SUPPORTED_URIS.Contains(uri, StringComparer.InvariantCultureIgnoreCase))
            {
                result = new CVOExtension(id);
            }
            else if (AudioLevelExtension.SUPPORTED_URIS.Contains(uri, StringComparer.InvariantCultureIgnoreCase))
            {
                result = new AudioLevelExtension(id);
            }
            else if (TransportWideCCExtension.SUPPORTED_URIS.Contains(uri, StringComparer.InvariantCultureIgnoreCase))
            {
                result = new TransportWideCCExtension(id);
            }
            
            if ( (result != null) &&  result.IsMediaSupported(media) )
            {
                result.Uri = uri;
                return result;
            }

            return null;
        }

        /// <summary>
        /// Returns true if the URI is supported by this extension
        /// </summary>
        /// <param name="uri"></param>
        /// <returns></returns>
        public bool SupportsExtension(string uri)
        {
            return SupportedURIs.Contains(uri, StringComparer.InvariantCultureIgnoreCase);
        }


        /// <summary>
        /// To create a RTP Header Extension
        /// </summary>
        /// <param name="id"><see cref="int"/> Id / extmap</param>
        /// <param name="uri"><see cref="String"/>uri</param>
        /// <param name="supportedURIs"><see cref="String"/> An array of supported RTP Header Extension URIs.</param>
        /// <param name="type"><see cref="RTPHeaderExtension"/>type (one or two bytes)</param>
        /// <param name="medias"><see cref="SDPMediaTypesEnum"/>media(s) supported by this extension - set null/empty if all medias are supported</param>
        public RTPHeaderExtension(int id, string uri, string[] supportedURIs, int extensionSize, RTPHeaderExtensionType type, params SDPMediaTypesEnum[] medias )
        {
            Id = id;
            Uri = uri;
            ExtensionSize = extensionSize;
            SupportedURIs = supportedURIs;
            Type = type;

            if (medias != null)
            {
                Medias = medias.ToList();
            }
            else
            {
                Medias = new List<SDPMediaTypesEnum>();
            }
        }

        // Id / "extmap"
        public int Id { get; internal set; }

        // Uri
        public string Uri { get; set; }

        //Supported URIs for this extension
        public string[] SupportedURIs { get; protected set; }

        public int ExtensionSize { get; }

        // Medias supported by this extension - if null/empty all medias are supported
        public List<SDPMediaTypesEnum> Medias { get;}

        // Type (one or two bytes)
        public RTPHeaderExtensionType Type { get; }

        public Boolean IsMediaSupported(SDPMediaTypesEnum media)
        {
            if (Medias.Count == 0)
            {
                return true;
            }

            return Medias.Contains(media);
        }

        // Function to call to set a new value to this extension
        public abstract void Set(Object obj);

        /// <summary>
        /// Writes the extension's payload into a destination buffer.
        /// </summary>
        /// <param name="destination">The buffer to write the payload into.</param>
        /// <returns>The number of bytes written.</returns>
        public abstract int Marshal(Span<byte> destination);

        /// <summary>
        /// Parses the extension's payload from a buffer slice.
        /// </summary>
        /// <param name="data">The buffer slice containing the extension payload.</param>
        public abstract object Unmarshal(RTPHeader header, ReadOnlySpan<byte> data);
    }

    public enum RTPHeaderExtensionType
    {
        OneByte,
        TwoByte
    }

    public class RTPHeaderExtensionData
    {
        // The data is now stored as a memory slice, not an owned array.
        public ReadOnlyMemory<byte> Data { get; }
        public int Id { get; }
        public RTPHeaderExtensionType Type { get; }

        /// <summary>
        /// Creates a new RTP Header Extension from a memory slice.
        /// This constructor is allocation-free.
        /// </summary>
        public RTPHeaderExtensionData(int id, ReadOnlyMemory<byte> data, RTPHeaderExtensionType type)
        {
            Id = id;
            Data = data;
            Type = type;
        }
    }
}
