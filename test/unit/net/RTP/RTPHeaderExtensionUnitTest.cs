using System;
using Microsoft.Extensions.Logging;
using SIPSorcery.Net;
using Xunit;

namespace SIPSorcery.UnitTests.Net
{
    [Trait("Category", "unit")]
    public class RTPHeaderExtensionUnitTest
    {
        private Microsoft.Extensions.Logging.ILogger logger = null;

        public RTPHeaderExtensionUnitTest(Xunit.Abstractions.ITestOutputHelper output)
        {
            logger = SIPSorcery.UnitTests.TestLogHelper.InitTestLogger(output);
        }

        [Fact]
        public void RTPHeaderExtensionAbsSendTime()
        {
            // Abs Send Time extension always uses the current time for data, and the fork removed the
            // static AbsSendTime(id, size, DateTimeOffset) helper that allowed a fixed time to be injected.
            // So only the extension header byte and marshalled size can be checked deterministically.

            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var extensionId = 2; // Id / Extmap of the extension
            var extension = new AbsSendTimeExtension(extensionId);

            var bytes = new byte[1 + AbsSendTimeExtension.RTP_HEADER_EXTENSION_SIZE];
            int written = extension.Marshal(bytes);

            Assert.Equal(bytes.Length, written);
            Assert.Equal(0x22, bytes[0]); // 2 for Extension ID and 2 for Length (AbsSendTimeExtension.RTP_HEADER_EXTENSION_SIZE - 1)
        }

        [Fact]
        public void RTPHeaderExtensionAudioLevel()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var extensionId = 2; // Id / Extmap of the extension
            var extension = new AudioLevelExtension(extensionId);

            // Create an audio Level
            var audioLevel = new AudioLevelExtension.AudioLevel()
            { 
                Voice = false,
                Level = 80 // "01010000" in bytes representation
            };
            extension.Set(audioLevel);

            // Marshal
            var bytesMarshalled = new byte[1 + AudioLevelExtension.RTP_HEADER_EXTENSION_SIZE];
            extension.Marshal(bytesMarshalled);

            Assert.Equal(0x20, bytesMarshalled[0]); // 2 for Extension ID and 0 for Length (AudioLevelExtension.RTP_HEADER_EXTENSION_SIZE - 1)
            Assert.Equal(Convert.ToByte("01010000", 2), bytesMarshalled[1]);

            // Unmarshal
            var audioLevelFromBytes = (AudioLevelExtension.AudioLevel)extension.Unmarshal(null, new byte[] { bytesMarshalled[1] });
            Assert.Equal(audioLevel.Voice, audioLevelFromBytes.Voice);
            Assert.Equal(audioLevel.Level, audioLevelFromBytes.Level);
        }

        [Fact]
        public void RTPHeaderExtensionCVO()
        {
            logger.LogDebug("--> {MethodName}", System.Reflection.MethodBase.GetCurrentMethod().Name);
            logger.BeginScope(System.Reflection.MethodBase.GetCurrentMethod().Name);

            var extensionId = 2; // Id / Extmap of the extension
            var extension = new CVOExtension(extensionId);

            // Create an CVO
            var cvo = new CVOExtension.CVO()
            {
                CameraBackFacing = true,
                HorizontalFlip = false,
                VideoRotation = CVOExtension.VideoRotation.CW_90
            };
            extension.Set(cvo);

            // Marshal
            var bytesMarshalled = new byte[1 + CVOExtension.RTP_HEADER_EXTENSION_SIZE];
            extension.Marshal(bytesMarshalled);
            Assert.Equal(0x20, bytesMarshalled[0]); // 2 for Extension ID and 0 for Length (CVOExtension.RTP_HEADER_EXTENSION_SIZE - 1)

            // Unmarshal
            var cvoFromBytes = (CVOExtension.CVO) extension.Unmarshal(null, new byte[] { bytesMarshalled[1] });
            Assert.Equal(cvo.CameraBackFacing, cvoFromBytes.CameraBackFacing);
            Assert.Equal(cvo.HorizontalFlip, cvoFromBytes.HorizontalFlip);
            Assert.Equal(cvo.VideoRotation, cvoFromBytes.VideoRotation);
        }
    }
}
