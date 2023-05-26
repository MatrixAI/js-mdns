import { testProp, fc } from '@fast-check/jest';
import { toQuestions, QClass, QType, fromName, encodeUInt16BE, concatUInt8Array } from '@/dns';

// For all integers in set of values in QType/QClass
const FC_QTYPES = fc.constantFrom(QType.A, QType.AAAA, QType.ANY, QType.CNAME, QType.NSEC, QType.OPT, QType.PTR, QType.TXT, QType.SRV);
const FC_QCLASSES = fc.constantFrom(QClass.ANY, QClass.IN);

const fc_question = fc.record({
  name: fc.domain(),
  type: FC_QTYPES,
  class: FC_QCLASSES,
});

describe('Question', () => {
  testProp('Decode - Single String Name', [fc_question], (originalQuestion) => {
    const buffer = fromName(originalQuestion.name);
    const nameLength = buffer.byteLength;
    const view = new DataView(buffer.buffer);

    const rawQuestion = concatUInt8Array(
      fromName(originalQuestion.name),
      encodeUInt16BE(originalQuestion.type),
      encodeUInt16BE(originalQuestion.class)
    );

    const decodedQuestion = toQuestions(rawQuestion, 0, 1);

    expect(decodedQuestion).toEqual({
      data: [originalQuestion],
      readBytes: rawQuestion.byteLength,
    });
  });

  testProp(
    'Decode - Multiple String Name',
    [fc.array(fc_question, { minLength: 2, maxLength: 10 })],
    (originalQuestions) => {
      const originalQuestionUint8Array = originalQuestions.flatMap((q) => {
        return [
          ...fromName(q.name),
          ...encodeUInt16BE(q.type),
          ...encodeUInt16BE(q.class),
        ];
      });

      const rawQuestion = new Uint8Array(originalQuestionUint8Array);

      const decodedQuestion = toQuestions(
        rawQuestion,
        0,
        originalQuestions.length,
      );

      expect(decodedQuestion).toEqual({
        data: originalQuestions,
        readBytes: rawQuestion.byteLength,
      });
    },
  );

  testProp('Decode - Pointer Name', [fc_question], (originalQuestion) => {
    // Universal Type and Class
    const typeAndClass = concatUInt8Array(
      encodeUInt16BE(originalQuestion.type),
      encodeUInt16BE(originalQuestion.class),
    );

    // Question with fake name to see if the pointer will select the correct record
    const questionWithFakeName = concatUInt8Array(
      fromName('fake.local'),
      typeAndClass,
    );

    // Uint8Array with a question and a pointer to that question
    const rawQuestion = concatUInt8Array(
      questionWithFakeName,
      fromName(originalQuestion.name),
      typeAndClass,

      // Pointer Question Starts with 0xC0
      new Uint8Array([0xc0, questionWithFakeName.byteLength]),
      typeAndClass,
    );

    const decodedQuestion = toQuestions(rawQuestion, 0, 3);

    expect(decodedQuestion.data[2].name).toEqual(originalQuestion.name);
    expect(decodedQuestion.readBytes).toEqual(rawQuestion.byteLength);
  });
});
